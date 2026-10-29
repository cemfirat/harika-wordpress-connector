<?php
declare(strict_types=1);
require __DIR__.'/fixtures/wordpress-pairing-runtime.php';
function expect($condition,string $message): void { if (!$condition) throw new RuntimeException($message); }
function fresh(): void {
    $GLOBALS['pairing_options']=[]; $GLOBALS['pairing_transients']=[]; $GLOBALS['pairing_user']=7;
    $GLOBALS['pairing_admins']=[7=>true,8=>true]; $GLOBALS['pairing_origin']='https://customer.example';
    update_option('ccf_gads_settings',['environment'=>'production','client_id'=>'legacy','site_id'=>'legacy-site',
        'endpoint'=>'https://control.example','encrypted_token'=>Harika_Connector::protect_pairing(str_repeat('old-',16))]);
}
function private_state(): array { return json_decode(Harika_Connector::open_pairing(get_option('harika_pairing_private_v1','')),true); }
function put_state(array $value): void { update_option('harika_pairing_private_v1',Harika_Connector::protect_pairing(json_encode($value))); }
function begin(): array {
    $url=Harika_Pairing::begin(); expect(is_string($url),'Begin returns a URL'); parse_str(parse_url($url,PHP_URL_QUERY),$params);
    expect(parse_url($url,PHP_URL_HOST)==='app.getharika.com','Fixed Harika origin');
    return $params;
}
$token='hwp_'.str_repeat('a',32).'.'.str_repeat('b',43);
$credential=['id'=>str_repeat('a',32),'token'=>$token,'client_id'=>'Client-A','site_id'=>'Site-A','environment'=>'production',
    'origin'=>'https://customer.example','control_endpoint'=>'https://control.example','organization'=>'Alpha','website'=>'Example'];
$verified=['state'=>'verified','activated_at'=>gmdate('c'),'origin'=>'https://customer.example','environment'=>'production','organization'=>'Alpha','website'=>'Example',
    'verification'=>['status'=>'verified','failed'=>[],'checks'=>array_fill_keys(['response_schema','token_accepted','client_id','site_id','environment','website_host','control_endpoint','reverse_control'],true)]];
$mode='checking'; $exchanges=0;
$GLOBALS['pairing_transport']=static function($url,$args) use (&$mode,&$exchanges,$credential,$verified) {
    expect(strpos($url,'https://app.getharika.com/wordpress/')===0,'No arbitrary transport origin');
    expect($args['redirection']===0 && $args['limit_response_size']===16384,'Bounded non-redirecting transport');
    $action=basename($url); $input=json_decode($args['body'],true);
    if ($action==='exchange') { $exchanges++; expect(strlen($input['verifier'])===43,'PKCE stays server-side'); $data=$credential; }
    elseif ($mode==='outage') return new WP_Error('offline','Simulated outage');
    elseif ($action==='complete' || $action==='check') $data=['state'=>'checking'];
    elseif ($mode==='bad-check') { $data=$verified; $data['verification']['checks']['reverse_control']=false; }
    elseif ($mode==='failed') $data=['state'=>'failed','activated_at'=>null,'error'=>'pairing_verification_failed'];
    elseif ($mode==='cancelled') $data=['state'=>'revoked','activated_at'=>null];
    elseif ($mode==='lost-activation') $data=['state'=>'revoked','activated_at'=>gmdate('c')];
    elseif ($mode==='verified') $data=$verified;
    elseif ($mode==='checking') $data=['state'=>'checking','activated_at'=>null,'origin'=>'https://customer.example','environment'=>'production'];
    else $data=['state'=>'checking'];
    return ['status'=>200,'body'=>json_encode(['data'=>$data])];
};
fresh(); $params=begin(); $intent=private_state()['intent'];
expect(!str_contains(get_option('harika_pairing_private_v1'),$intent['verifier']),'Verifier encrypted at rest');
$challenge=Harika_Pairing::challenge(new Pairing_Request([],['state'=>$params['state']]));
expect($challenge instanceof WP_REST_Response && $challenge->data['code_challenge']===$params['code_challenge'],'Actual challenge binds PKCE');
expect(!str_contains(json_encode($challenge->data),'user') && !str_contains(json_encode($challenge->data),$intent['verifier']),'Public proof has no user or verifier');
expect($challenge->headers['Cache-Control']==='no-store','Proof is never cached');
$GLOBALS['pairing_user']=8; expect(is_wp_error(Harika_Pairing::finish(str_repeat('c',43),$params['state'])),'Different WP admin cannot finish');
$GLOBALS['pairing_user']=7; expect(is_wp_error(Harika_Pairing::finish(str_repeat('c',43),str_repeat('d',43))),'Wrong state rejected');
$GLOBALS['pairing_admins'][7]=false;
expect(is_wp_error(Harika_Pairing::challenge(new Pairing_Request([],['state'=>$params['state']]))),'Revoked WP rights invalidate proof');
expect(is_wp_error(Harika_Pairing::begin()),'Non-admin cannot begin'); $GLOBALS['pairing_admins'][7]=true;
$state=private_state(); $state['intent']['expires']=time()-1; put_state($state);
expect(is_wp_error(Harika_Pairing::finish(str_repeat('c',43),$params['state'])),'Expired state rejected');
$params=begin(); $GLOBALS['pairing_origin']='https://foreign.example';
expect(is_wp_error(Harika_Pairing::finish(str_repeat('c',43),$params['state'])),'Cloned/changed host rejected');
$GLOBALS['pairing_origin']='https://customer.example';
$result=Harika_Pairing::finish(str_repeat('c',43),$params['state']);
expect($result===['state'=>'checking'],'Only checking after exchange');
expect(Harika_Pairing::authorize_control(new Pairing_Request())===true,'Pending key can prove the connection');
$writeRequest = new class { public function get_method() { return 'POST'; } public function get_route() { return '/ccf-sites/v1/changes/apply'; } };
expect(is_wp_error(Harika_Pairing::authorize_control($writeRequest)),'Pending key cannot authorize WordPress writes');
expect(Harika_Connector::site_token()===$token && Harika_Connector::client_id()==='Client-A','Candidate installed exactly, no lowercase drift');
expect(!str_contains(get_option('harika_pairing_private_v1'),$token),'Candidate encrypted');
expect(is_wp_error(Harika_Pairing::finish(str_repeat('c',43),$params['state'])) && $exchanges===1,'Callback is one-time');
expect(is_wp_error(Harika_Pairing::begin()),'Unresolved candidate cannot be overwritten');
$mode='outage'; expect(is_wp_error(Harika_Pairing::authorize_control(new Pairing_Request())),'Authority outage rejects signed calls'); expect(is_wp_error(Harika_Pairing::status()) && Harika_Connector::site_token()===$token,'Unknown outcome retains candidate');
$mode='bad-check'; expect(Harika_Pairing::status()['state']==='not_verified','One false field cannot appear green');
$mode='failed'; expect(Harika_Pairing::status()['state']==='failed' && Harika_Connector::site_token()===str_repeat('old-',16),'Terminal never-active failure restores legacy');
$params=begin(); Harika_Pairing::finish(str_repeat('c',43),$params['state']);
$mode='cancelled'; Harika_Pairing::cancel(); expect(Harika_Connector::site_token()===str_repeat('old-',16),'Pre-activation cancellation preserves existing configuration');
$params=begin(); Harika_Pairing::finish(str_repeat('c',43),$params['state']);
$mode='verified'; expect(Harika_Pairing::status()['state']==='verified','All fields activate');
expect(Harika_Pairing::authorize_control($writeRequest)===true,'Active server-authorized key supports existing write capability');
expect(isset(private_state()['active']) && !isset(private_state()['candidate']),'Activation commits and removes candidate');
$GLOBALS['pairing_origin']='https://clone.example'; expect(Harika_Connector::site_token()==='','Cloned site cannot use active token');
$GLOBALS['pairing_origin']='https://customer.example';
$mode='lost-activation'; Harika_Pairing::cancel(); expect(Harika_Connector::site_token()==='','Activated revocation never falls back to legacy');
fresh(); $params=begin(); Harika_Pairing::finish(str_repeat('c',43),$params['state']);
$mode='lost-activation'; Harika_Pairing::cancel(); expect(Harika_Connector::site_token()==='','Lost success followed by revoke never restores old config');
fresh(); update_option('harika_pairing_private_v1','corrupt'); expect(Harika_Connector::site_token()==='','Corrupt storage fails closed');
fresh(); $GLOBALS['pairing_options']=[]; Harika_Pairing::activate(true); expect(!$GLOBALS['pairing_transients'],'No network activation redirect');
fresh(); $GLOBALS['pairing_options']=[]; $_REQUEST['activate-multi']=1; Harika_Pairing::activate(); expect(!$GLOBALS['pairing_transients'],'No bulk activation redirect'); unset($_REQUEST['activate-multi']);
fresh(); $GLOBALS['pairing_options']=[]; Harika_Pairing::activate(); expect(get_transient('harika_pairing_redirect_7')===1,'Individual first activation starts setup');
$GLOBALS['pairing_transients']=[]; Harika_Pairing::activate(); expect(!$GLOBALS['pairing_transients'],'Reactivation/update does not force another redirect');
fresh(); define('CCF_GADS_SITE_TOKEN',str_repeat('locked-',10)); expect(is_wp_error(Harika_Pairing::begin()),'Never silently replace a constant-based configuration');
echo "WordPress pairing authority, encrypted persistence, failure recovery and activation tests passed.\n";
