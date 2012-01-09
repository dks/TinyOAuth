<?php
// Typical Errs on OAuth:
// 1. When building base string: "http://" and "example.com" ONLY are lower case, rest of url can be uppercase
// 2. Base string includes GET params, but Authorization header does NOT!
// 3. Make sure parameters are relevant to the Phase(Request), i.e. NO callback at access token, NO verifier at 
// final requests etc.
// 4. Watch for redundant urlencodings, i.e. if use http_build_query it will make urlencode automatically.

class TinyOAuth{
	private $ath=null;	// OAuth Athorization array (what is sent)
	private $uag=null;	// Url Arguments (used internally)
	private $url=null;	// Url (for current request)
	private $rm="GET";	// Request Method (requests customized for GET only)
	private $db=false;	// Debug Messages
	private $sm="HMAC-SHA1";	// Signature method (requests customized for HMAC-SHA1 only)

	public  $cfg=null;	// Configuration array
	public  $timesh=0;	// TimeStamp offset - for wrong timed machines =)
	public  $sfp="oa";	// File Storage Name/Path
	public  $av="1.0";	// OAuth Version

	function __construct($c,$debug=false,$storage=null,$timeshift=null){
		$this->db=$debug;
		if (!is_array($c)) { echo "Constructor parameters must be array!"; exit(125); }
		$ck=array_keys($c);
		if (!in_array("authorizeUrl",$ck) ||
				!in_array("requestTokenUrl",$ck) ||
				!in_array("accessTokenUrl",$ck) ||
				!in_array("consumerKey",$ck) ||
				!in_array("consumerSecret",$ck) ||
				!in_array("callbackUrl",$ck))	{ 
					echo "<h1>Parameters Array Incomplete. Must have: authorizeUrl,requestTokenUrl,".
						"accessTokenUrl,consumerKey,consumerSecret,callbackUrl</h1>";	
					exit(125);
		}
		$this->cfg=$c;
		$this->elog($this->cfg,"USER_INFO");
		if ($storage) $this->elog($this->sfp=$storage,"USER_DEFINED_STORAGE");
		if ($timeshift) $this->elog($this->timesh=$timeshift,"USER_DEFINED_TIMESHIFT");
	}
	
	function elog($data,$name=null){
		if ($this->db) { echo "<pre>".(($name)?$name.": ":""); print_r($data); echo "</pre>"; }
		return $data;
	}
	
	function save(){
		if (@file_put_contents($this->sfp,serialize($this->cfg))!==false) return true; else return false;
	}

	function restore(){
		if ((@$data=file_get_contents($this->sfp))!==false){
			$this->cfg=unserialize($data); 
			return true;
		} else return false;
	}
	
	function isTokenValid(){
		if (isset($this->cfg['tokenValidBefore']) && (time() < $this->cfg['tokenValidBefore']))
			return true; else return false;
	}
	
	function isSessionValid(){
		if (isset($this->cfg['sessionValidBefore']) && (time() < $this->cfg['sessionValidBefore']))
			return true; else return false;
	}

	//////////////////// OAUTH ROUTINES ///////////////////////

	function fillAuthorizationParams(){
		$this->ath['oauth_consumer_key']=$this->cfg['consumerKey'];
		if (isset($this->cfg['oauth_token'])) $this->ath['oauth_token']=$this->cfg['oauth_token'];
		$this->ath['oauth_nonce']=$this->getNonce();
		$this->ath['oauth_timestamp']=$this->getTimes();
		$this->ath['oauth_signature_method']=$this->sm;
		$this->ath['oauth_version']=$this->av;
		$this->elog($this->ath,"AUTHORIZATION_PARAMS");
	}
	function getNonce(){ return $this->elog(md5(uniqid(rand(),true)),"NONCE");	}
	function getTimes(){ return $this->elog(time() + $this->timesh,"TIMESTAMP"); }
	function getSignKey(){ return $this->elog(rawurlencode($this->cfg['consumerSecret']).'&'.
			(isset($this->cfg['oauth_token_secret'])?rawurlencode($this->cfg['oauth_token_secret']):""),"SIGN_KEY");
	}
	function getBaseString(){ return $this->elog($this->rm.'&'.rawurlencode($this->getNormalizedUrl()).
		'&'.rawurlencode($this->getSignableParams()),"BASE_STRING");
	}
	function getSignableParams(){
		if ($this->uag){
			foreach(explode("&",$this->uag) as $i){
				list($k,$v)=explode("=",$i);
				$extra[$k]=$v; }}
		if (isset($extra) && $extra) $params=array_merge($this->ath,$extra); else $params=$this->ath;
		ksort($params); $params2=null;
		$this->elog($params,"SIGNABLE_PARAMS_ARRAY");
		foreach($params as $key => $val) $params2.=rawurlencode($key).'='.rawurlencode($val).'&';
		$params2 = substr($params2,0,-1);
		return $this->elog($params2,"SIGNABLE_PARAMS_STRING");
	}
	function getNormalizedUrl(){
    $parts = parse_url($this->url);
    $scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
    $port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
    $host = (isset($parts['host'])) ? strtolower($parts['host']) : '';
    $path = (isset($parts['path'])) ? $parts['path'] : '';
    if (($scheme == 'https' && $port != '443')
        || ($scheme == 'http' && $port != '80')) {
      $host = "$host:$port";
    }
		if (isset($parts['query'])) $this->uag=$parts['query'];
    return $this->elog("$scheme://$host$path","NORMALIZED_URL");
  }
	function signRequest(){
		$this->elog($this->ath['oauth_signature']=base64_encode(hash_hmac('sha1',
			$this->getBaseString(),$this->getSignKey(),true)),"SIGNATURE");
	}
	function performRequest(){
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL,$this->elog($this->url,"CALLED_URL"));
		curl_setopt($ch, CURLOPT_HTTPHEADER,array($this->getAuthHeader()));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$result = curl_exec ($ch);
		$this->elog(curl_getinfo($ch),"CURL_INFO");
		curl_close ($ch);
		return $this->elog($result,"SERVER_RESPONSE");
	}
	function getAuthHeader(){
		foreach($this->ath as $k => $v) $s[]=sprintf("%s=\"%s\"",rawurlencode($k), rawurlencode($v));
		return $this->elog("Authorization: OAuth ".implode(",", $s),"AUTH_HEADER");
	}
	/////////////////////// HIGH LEVEL CALLS ///////////////////////////
	
	function getRequestToken(){
		$this->elog(str_pad("GETTING_REQUEST_TOKEN",130,"=",STR_PAD_BOTH));
		$this->url=$this->cfg['requestTokenUrl'];
		if (isset($this->cfg['oauth_token'])) unset($this->cfg['oauth_token']);
		if (isset($this->cfg['oauth_token_secret'])) unset($this->cfg['oauth_token_secret']);
		$this->ath=null;
		$this->ath['oauth_callback']=$this->cfg['callbackUrl'];
		$this->fillAuthorizationParams();
		$this->signrequest();
		$res=$this->performRequest();
		parse_str($res,$p);
		if (isset($p['oauth_token'])) $this->cfg['oauth_token']=$p['oauth_token'];
		if (isset($p['oauth_token_secret'])) $this->cfg['oauth_token_secret']=$p['oauth_token_secret'];
		$this->save();
		return $res;
	}
	
	function getAccessToken(){
		$this->elog(str_pad("GETTING_ACCESS_TOKEN",130,"=",STR_PAD_BOTH));
		if (!isset($this->cfg['oauth_token']) || 
				!isset($this->cfg['oauth_token_secret']) || 
				!isset($this->cfg['oauth_verifier'])){
					throw new Exception("<h1>ERROR, missing oauth_token and/or oauth_token_secret and/or".
						" oauth_verifier in configuration (\$cfg)!</h1>");
					exit(125);
		}	
		$this->url=$this->cfg['accessTokenUrl'];
		$this->ath=null;
		if (isset($this->cfg['oauth_verifier'])) $this->ath['oauth_verifier']=$this->cfg['oauth_verifier'];
		$this->fillAuthorizationParams();
		$this->signrequest();
		$res=$this->performRequest();
		parse_str($res,$p);
		if (isset($p['oauth_token'])) $this->cfg['oauth_token']=$p['oauth_token'];
		if (isset($p['oauth_token_secret'])) $this->cfg['oauth_token_secret']=$p['oauth_token_secret'];
		if (isset($p['oauth_session_handle'])) $this->cfg['oauth_session_handle']=$p['oauth_session_handle'];
		if (isset($p['oauth_authorization_expires_in'])) 
			$this->cfg['sessionValidBefore']=time()+$p['oauth_authorization_expires_in'];
		if (isset($p['oauth_expires_in'])) 
			$this->cfg['tokenValidBefore']=time()+$p['oauth_expires_in'];
		if (isset($this->cfg['oauth_verifier'])) unset($this->cfg['oauth_verifier']);
		$this->save();
		return $res;
	}
	
	function renewAccessToken(){
		$this->elog(str_pad("RENEWING_ACCESS_TOKEN",130,"=",STR_PAD_BOTH));
		if (!isset($this->cfg['oauth_token']) || 
				!isset($this->cfg['oauth_token_secret']) || 
				!isset($this->cfg['oauth_session_handle'])){
					echo "<h1>ERROR, missing oauth_token and/or oauth_token_secret and/or".
						"oauth_session_handle in configuration (\$cfg)!</h1>";
					exit(125);
		}	
		$this->url=$this->cfg['accessTokenUrl'];
		$this->ath=null;
		if (isset($this->cfg['oauth_session_handle'])) 
			$this->ath['oauth_session_handle']=$this->cfg['oauth_session_handle'];
		$this->fillAuthorizationParams();
		$this->signrequest();
		$res=$this->performRequest();
		parse_str($res,$p);
		if (isset($p['oauth_token'])) $this->cfg['oauth_token']=$p['oauth_token'];
		if (isset($p['oauth_token_secret'])) $this->cfg['oauth_token_secret']=$p['oauth_token_secret'];
		if (isset($p['oauth_session_handle'])) $this->cfg['oauth_session_handle']=$p['oauth_session_handle'];
		if (isset($p['oauth_authorization_expires_in'])) 
			$this->cfg['sessionValidBefore']=time()+$p['oauth_authorization_expires_in'];
		if (isset($this->cfg['oauth_verifier'])) unset($this->cfg['oauth_verifier']);
		$this->save();
		return $res;
	}
	
	function doSignedApiCall($url){
		$this->elog(str_pad("MAKING_SIGNED_API_CALL",130,"=",STR_PAD_BOTH));
		$this->url=$url;
		$this->ath=null;
		$this->fillAuthorizationParams();
		$this->signrequest();
		return $res=$this->performRequest();
	}
}//EOC 
?>
