<?php
///////////////////////////////////////////////////////////////////////////////
// This is just example skeleton of what you could do.                       //
//                                                                           //
// It is taken from the real project, however since it uses "oauth_login"    //
// function (not included here) that logins automatically using user         //
// credentials, it is not quite compliant to OAuth philosophy, since it      //
// skips user login/password input phases.                                   //
//                                                                           //
// To cut is short - this example will not work as it is. You have to        //
// customise it to your needs.                                               //
///////////////////////////////////////////////////////////////////////////////
require_once("TinyOAuth.php");

function makeSignedCall($URL){
	$oauthConfig = array(
		'authorizeUrl'=>"https://auth.login.yahoo.co.jp/oauth/v2/request_auth",
		'requestTokenUrl'=>"https://auth.login.yahoo.co.jp/oauth/v2/get_request_token",
		'accessTokenUrl'=>"https://auth.login.yahoo.co.jp/oauth/v2/get_token",
		'consumerKey'=>$appid, // your application id here
		'consumerSecret'=>$cSecret, // your consumer secret here
		'callbackUrl'=>"oob" // currently only oob implemented
	);

	$toa=new TinyOAuth($oauthConfig,false,"cookies/oa.txt");
	$toa->restore();
	if (!$toa->isTokenValid()){
		if (!$toa->isSessionValid()){
			parse_str($toa->getRequestToken()); 
			$verifier=oauth_login($oauth_token,$oauth_token_secret,$xoauth_request_auth_url);
			$toa->getAccessToken();
		} else $toa->renewAccessToken();
	}
	return $toa->doSignedApiCall($URL);
}?>
