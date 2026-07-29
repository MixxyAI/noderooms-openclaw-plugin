<?php
if (!defined('ABSPATH')) {
    exit;
}

interface NR_AIG_Action_Dispatcher_Interface
{
    public function bridge_ready();
    public function dispatch(array $guest, array $action, $original_request);
}
