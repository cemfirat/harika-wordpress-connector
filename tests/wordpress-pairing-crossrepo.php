<?php
/** Loopback-only CLI bridge; no WordPress credentials, events or production calls. */
declare(strict_types=1);
require __DIR__.'/fixtures/wordpress-pairing-runtime.php';
$input=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
$file=getenv('HARIKA_PAIRING_FIXTURE_STATE');
if (!is_string($file) || strpos($file,sys_get_temp_dir().'/')!==0) throw new RuntimeException('Isolated state path required.');
if (is_file($file)) {
    $saved=json_decode(file_get_contents($file),true,32,JSON_THROW_ON_ERROR);
    $GLOBALS['pairing_options']=$saved['options']; $GLOBALS['pairing_transients']=$saved['transients'];
}
$GLOBALS['pairing_user']=(int)($input['user'] ?? 7);
$GLOBALS['pairing_reverse_mismatch']=!empty($input['reverseMismatch']);
if (isset($input['origin'])) $GLOBALS['pairing_origin']=$input['origin'];
$GLOBALS['pairing_transport']=static function ($url,$args) {
    $parsed=parse_url($url); $origin=($parsed['scheme'] ?? '').'://'.($parsed['host'] ?? '');
    if ($origin==='https://app.getharika.com' && preg_match('#^/wordpress/(exchange|complete|status|check|revoke)$#',$parsed['path'] ?? '')) $target=getenv('HARIKA_PAIRING_FIXTURE_APP');
    elseif ($origin==='https://ccf-sites-ads-events-n6qc7lsmga-ew.a.run.app' && ($parsed['path'] ?? '')==='/v1/connection-check') $target=getenv('HARIKA_PAIRING_FIXTURE_EVENTS');
    else throw new RuntimeException('Unexpected network target.');
    if (!preg_match('#^http://127\.0\.0\.1:[0-9]{2,5}$#',(string)$target)) throw new RuntimeException('Loopback required.');
    if (($parsed['path'] ?? '')==='/v1/connection-check' && $GLOBALS['pairing_reverse_mismatch']) { $payload=json_decode($args['body'],true); $payload['environment']='staging'; $args['body']=json_encode($payload); }
    $headers=[]; foreach ($args['headers'] as $key=>$value) $headers[]=$key.': '.$value;
    $context=stream_context_create(['http'=>['method'=>'POST','header'=>implode("\r\n",$headers),'content'=>$args['body'],'timeout'=>15,'ignore_errors'=>true,'follow_location'=>0]]);
    $body=@file_get_contents($target.$parsed['path'],false,$context);
    if ($body===false) return new WP_Error('offline_transport','Isolated server unavailable.');
    preg_match('#HTTP/\S+ (\d+)#',$http_response_header[0] ?? '',$match);
    return ['status'=>(int)($match[1] ?? 500),'body'=>$body];
};
$action=$input['action'] ?? '';
switch ($action) {
    case 'seed':
        update_option('ccf_gads_settings',['environment'=>'production','client_id'=>'client-a','site_id'=>'sa',
            'endpoint'=>'https://ccf-sites-ads-events-n6qc7lsmga-ew.a.run.app','encrypted_token'=>Harika_Connector::protect_pairing(str_repeat('isolated-legacy-',4))]);
        $result=['state'=>'seeded']; break;
    case 'begin': $result=Harika_Pairing::begin(); break;
    case 'challenge': $result=Harika_Pairing::challenge(new Pairing_Request([],['state'=>$input['state']])); break;
    case 'finish': $result=Harika_Pairing::finish($input['code'],$input['state']); break;
    case 'status': $result=Harika_Pairing::status(); break;
    case 'check': $result=Harika_Pairing::check(); break;
    case 'cancel': $result=Harika_Pairing::cancel(); break;
    case 'connection':
        $url=parse_url($input['url']);
        if (($url['host'] ?? '')!=='customer.example' || ($url['path'] ?? '')!=='/wp-json/ccf-sites/v1/connection') throw new RuntimeException('Unexpected WP route.');
        parse_str($url['query'] ?? '',$query);
        $request=new Pairing_Request($input['headers'],$query);
        $authorized=Harika_Control::authorize($request);
        $result=$authorized===true ? Harika_Status_Overlay::connection() : $authorized; break;
    default: throw new RuntimeException('Unexpected fixture action.');
}
file_put_contents($file,json_encode(['options'=>$GLOBALS['pairing_options'],'transients'=>$GLOBALS['pairing_transients']],JSON_THROW_ON_ERROR));
chmod($file,0600);
if (is_wp_error($result)) $output=['status'=>$result->data['status'] ?? 409,'error'=>$result->code];
elseif ($result instanceof WP_REST_Response) $output=['status'=>$result->status,'data'=>$result->data];
else $output=['status'=>200,'data'=>$result];
echo json_encode($output,JSON_THROW_ON_ERROR);
