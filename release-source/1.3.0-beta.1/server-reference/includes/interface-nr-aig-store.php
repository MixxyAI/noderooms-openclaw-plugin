<?php
if (!defined('ABSPATH')) {
    exit;
}

interface NR_AIG_Store_Interface
{
    public function ensure_schema();
    public function schema_ready();
    public function reserve_action(array $guest, array $action);
    public function claim_dispatch($row_id);
    public function get_action($guest_key, $action_id);
    public function get_receipt($receipt_id);
    public function mark_committed($row_id, $object_id, $public_url, array $safe_result);
    public function mark_failed($row_id, $error_code, $error_message);
    public function mark_unknown($row_id, $error_code, $error_message);
    public function mark_expired_reserved_failed();
    public function mark_stale_processing_unknown();
    public function cleanup();
}
