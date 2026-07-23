<?php
if (!defined('ABSPATH')) {
    exit;
}

interface NR_AIG_Guest_Authenticator_Interface
{
    public function permission($request);
    public function context($request);
    public function bridge_ready();
}
