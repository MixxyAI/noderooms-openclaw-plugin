<?php
if (!defined('ABSPATH')) {
    exit;
}

final class NR_AIG_Wpdb_Store implements NR_AIG_Store_Interface
{
    const SCHEMA_OPTION = 'nr_aig_schema_version';
    const SCHEMA_VERSION = '2';
    const RESERVATION_TTL_SECONDS = 7200;
    const PROCESSING_STALE_SECONDS = 120;
    const RETENTION_DAYS = 90;

    private $wpdb;
    private $table;

    public function __construct($wpdb_instance = null)
    {
        if ($wpdb_instance === null) {
            global $wpdb;
            $wpdb_instance = $wpdb;
        }
        $this->wpdb = $wpdb_instance;
        $this->table = $this->wpdb->prefix . 'nr_action_idempotency';
    }

    public function ensure_schema()
    {
        $charset_collate = $this->wpdb->get_charset_collate();
        $sql = "CREATE TABLE {$this->table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            guest_key char(64) NOT NULL,
            agent_id bigint(20) unsigned NOT NULL,
            action_id varchar(64) NOT NULL,
            action_type varchar(32) NOT NULL,
            fingerprint_sha256 char(64) NOT NULL,
            state varchar(16) NOT NULL DEFAULT 'reserved',
            receipt_id varchar(64) NOT NULL,
            public_write_attempted tinyint(1) NOT NULL DEFAULT 0,
            dispatch_count tinyint(3) unsigned NOT NULL DEFAULT 0,
            object_id bigint(20) unsigned DEFAULT NULL,
            public_url text NULL,
            error_code varchar(128) DEFAULT NULL,
            error_message varchar(512) DEFAULT NULL,
            result_json longtext NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            committed_at datetime DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY guest_action (guest_key,action_id),
            UNIQUE KEY receipt_id (receipt_id),
            KEY state_updated (state,updated_at),
            KEY state_expires (state,expires_at)
        ) {$charset_collate};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        $ready = $this->schema_ready();
        if ($ready) {
            update_option(self::SCHEMA_OPTION, self::SCHEMA_VERSION, false);
        }
        return $ready;
    }

    public function schema_ready()
    {
        $found = $this->wpdb->get_var(
            $this->wpdb->prepare('SHOW TABLES LIKE %s', method_exists($this->wpdb, 'esc_like') ? $this->wpdb->esc_like($this->table) : $this->table)
        );
        if ((string) $found !== (string) $this->table) {
            return false;
        }

        $columns = $this->wpdb->get_results("SHOW COLUMNS FROM `{$this->table}`", ARRAY_A);
        if (!is_array($columns)) {
            return false;
        }
        $actual_columns = array();
        foreach ($columns as $column) {
            if (!isset($column['Field'])) {
                return false;
            }
            $actual_columns[] = (string) $column['Field'];
        }
        $expected_columns = array(
            'id', 'guest_key', 'agent_id', 'action_id', 'action_type',
            'fingerprint_sha256', 'state', 'receipt_id',
            'public_write_attempted', 'dispatch_count', 'object_id',
            'public_url', 'error_code', 'error_message', 'result_json',
            'created_at', 'updated_at', 'expires_at', 'committed_at',
        );
        if ($actual_columns !== $expected_columns) {
            return false;
        }

        $indexes = $this->wpdb->get_results("SHOW INDEX FROM `{$this->table}`", ARRAY_A);
        if (!is_array($indexes)) {
            return false;
        }
        $index_map = array();
        foreach ($indexes as $index) {
            if (!isset($index['Key_name'], $index['Seq_in_index'], $index['Column_name'], $index['Non_unique'])) {
                return false;
            }
            $name = (string) $index['Key_name'];
            $sequence = (int) $index['Seq_in_index'];
            if (!isset($index_map[$name])) {
                $index_map[$name] = array('columns' => array(), 'non_unique' => (int) $index['Non_unique']);
            }
            $index_map[$name]['columns'][$sequence] = (string) $index['Column_name'];
            $index_map[$name]['non_unique'] = (int) $index['Non_unique'];
        }
        foreach ($index_map as &$definition) {
            ksort($definition['columns'], SORT_NUMERIC);
            $definition['columns'] = array_values($definition['columns']);
        }
        unset($definition);

        return $this->index_matches($index_map, 'PRIMARY', array('id'), false)
            && $this->index_matches($index_map, 'guest_action', array('guest_key', 'action_id'), false)
            && $this->index_matches($index_map, 'receipt_id', array('receipt_id'), false)
            && $this->index_matches($index_map, 'state_updated', array('state', 'updated_at'), true)
            && $this->index_matches($index_map, 'state_expires', array('state', 'expires_at'), true);
    }

    public function reserve_action(array $guest, array $action)
    {
        $now = gmdate('Y-m-d H:i:s');
        $expires_at = gmdate('Y-m-d H:i:s', time() + self::RESERVATION_TTL_SECONDS);
        try {
            $receipt_id = 'nrreceipt_' . bin2hex(random_bytes(16));
        } catch (Throwable $error) {
            unset($error);
            return new WP_Error('NR_ACTION_RECEIPT_ID_UNAVAILABLE', 'A secure canonical receipt id could not be created.', array('status' => 500));
        }

        $sql = $this->wpdb->prepare(
            "INSERT IGNORE INTO `{$this->table}`
            (guest_key,agent_id,action_id,action_type,fingerprint_sha256,state,receipt_id,public_write_attempted,dispatch_count,created_at,updated_at,expires_at)
            VALUES (%s,%d,%s,%s,%s,'reserved',%s,0,0,%s,%s,%s)",
            $guest['guest_key'],
            (int) $guest['agent_id'],
            $action['action_id'],
            $action['action_type'],
            $action['fingerprint_sha256'],
            $receipt_id,
            $now,
            $now,
            $expires_at
        );
        $inserted = $this->wpdb->query($sql);
        if ($inserted === false) {
            return new WP_Error('NR_ACTION_RESERVATION_FAILED', 'The action reservation could not be created safely.', array('status' => 500));
        }

        $row = $this->get_action($guest['guest_key'], $action['action_id']);
        if (!$row) {
            return new WP_Error('NR_ACTION_RESERVATION_FAILED', 'The action reservation is unavailable after creation.', array('status' => 500));
        }
        if (!hash_equals((string) $row['fingerprint_sha256'], (string) $action['fingerprint_sha256'])
            || (string) $row['action_type'] !== (string) $action['action_type']) {
            return new WP_Error('IDEMPOTENCY_FINGERPRINT_MISMATCH', 'The action id is already bound to a different immutable payload.', array('status' => 409));
        }

        return array(
            'owner' => (int) $inserted === 1,
            'idempotency_status' => (int) $inserted === 1 ? 'created' : 'replayed',
            'row' => $row,
        );
    }

    public function claim_dispatch($row_id)
    {
        $now = gmdate('Y-m-d H:i:s');
        $updated = $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE `{$this->table}` SET state = 'processing', public_write_attempted = 1, dispatch_count = 1, updated_at = %s WHERE id = %d AND state = 'reserved' AND public_write_attempted = 0 AND dispatch_count = 0 AND expires_at > %s",
                $now,
                (int) $row_id,
                $now
            )
        );
        if ($updated === false) {
            return new WP_Error('NR_ACTION_DISPATCH_CLAIM_FAILED', 'The action could not be claimed for one-time dispatch.', array('status' => 500));
        }
        return (int) $updated === 1;
    }

    public function get_action($guest_key, $action_id)
    {
        $row = $this->wpdb->get_row(
            $this->wpdb->prepare(
                "SELECT * FROM `{$this->table}` WHERE guest_key = %s AND action_id = %s LIMIT 1",
                $guest_key,
                $action_id
            ),
            ARRAY_A
        );
        return is_array($row) ? $row : null;
    }

    public function get_receipt($receipt_id)
    {
        $row = $this->wpdb->get_row(
            $this->wpdb->prepare("SELECT * FROM `{$this->table}` WHERE receipt_id = %s LIMIT 1", $receipt_id),
            ARRAY_A
        );
        return is_array($row) ? $row : null;
    }

    public function mark_committed($row_id, $object_id, $public_url, array $safe_result)
    {
        $now = gmdate('Y-m-d H:i:s');
        $updated = $this->wpdb->update(
            $this->table,
            array(
                'state' => 'committed',
                'object_id' => (int) $object_id,
                'public_url' => (string) $public_url,
                'error_code' => null,
                'error_message' => null,
                'result_json' => wp_json_encode($safe_result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                'updated_at' => $now,
                'committed_at' => $now,
            ),
            array('id' => (int) $row_id, 'state' => 'processing'),
            array('%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s'),
            array('%d', '%s')
        );
        return $updated === 1;
    }

    public function mark_failed($row_id, $error_code, $error_message)
    {
        return $this->mark_terminal($row_id, 'failed', $error_code, $error_message);
    }

    public function mark_unknown($row_id, $error_code, $error_message)
    {
        return $this->mark_terminal($row_id, 'unknown', $error_code, $error_message);
    }

    public function mark_expired_reserved_failed()
    {
        $now = gmdate('Y-m-d H:i:s');
        return $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE `{$this->table}` SET state = 'failed', error_code = 'ACTION_RESERVATION_EXPIRED', error_message = %s, updated_at = %s WHERE state = 'reserved' AND expires_at <= %s",
                'The server-side action reservation expired before any public write was attempted.',
                $now,
                $now
            )
        );
    }

    public function mark_stale_processing_unknown()
    {
        $threshold = gmdate('Y-m-d H:i:s', time() - self::PROCESSING_STALE_SECONDS);
        $now = gmdate('Y-m-d H:i:s');
        return $this->wpdb->query(
            $this->wpdb->prepare(
                "UPDATE `{$this->table}` SET state = 'unknown', error_code = 'ACTION_PROCESSING_STALE', error_message = %s, updated_at = %s WHERE state = 'processing' AND updated_at < %s",
                'The original dispatch did not finish locally. Replay remains blocked because the public outcome may be uncertain.',
                $now,
                $threshold
            )
        );
    }

    public function cleanup()
    {
        $this->mark_expired_reserved_failed();
        $this->mark_stale_processing_unknown();
        $threshold = gmdate('Y-m-d H:i:s', time() - (self::RETENTION_DAYS * DAY_IN_SECONDS));
        return $this->wpdb->query(
            $this->wpdb->prepare(
                "DELETE FROM `{$this->table}` WHERE state IN ('committed','failed','unknown') AND updated_at < %s",
                $threshold
            )
        );
    }

    private function mark_terminal($row_id, $state, $error_code, $error_message)
    {
        $now = gmdate('Y-m-d H:i:s');
        $updated = $this->wpdb->update(
            $this->table,
            array(
                'state' => $state,
                'error_code' => substr((string) $error_code, 0, 128),
                'error_message' => NR_AIG_Canonical::safe_error_message($error_message),
                'updated_at' => $now,
            ),
            array('id' => (int) $row_id, 'state' => 'processing'),
            array('%s', '%s', '%s', '%s'),
            array('%d', '%s')
        );
        return $updated === 1;
    }

    private function index_matches(array $index_map, $name, array $columns, $non_unique)
    {
        if (!isset($index_map[$name]['columns'], $index_map[$name]['non_unique'])) {
            return false;
        }
        return $index_map[$name]['columns'] === $columns
            && (bool) $index_map[$name]['non_unique'] === (bool) $non_unique;
    }
}
