<?php

namespace NA\Core\Controllers;

class GlobalOAuth2Controller extends \NA\FrontController
{
	protected static function configureServer()
	{
		if (!class_exists('OAuth2_Server'))
		{
			require_once(REP_GLOBAL.'vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
			\OAuth2_Autoloader::register();
		}

		$pdo = \NPDO::get();
		$storage = new \OAuth2_Storage_Pdo($pdo);

		// create your server again
		$server = new \OAuth2_Server($storage/*, array('allow_implicit' => true)*/);

		$supportedScopes = static::getSupportedScopes();
		$memory = new \OAuth2_Storage_Memory(array(
												 'default_scope' => static::getDefaultScopes(),
												 'supported_scopes' => $supportedScopes
											 ));
		$scopeUtil = new \NA\Core\OAuth2\Scope($memory);

		$server->setScopeUtil($scopeUtil);

		// Add the "Authorization Code" grant type (this is required for authorization flows)
		$server->addGrantType(new \OAuth2_GrantType_AuthorizationCode($storage));
		$server->addGrantType(new \OAuth2_GrantType_ClientCredentials($storage));
		$server->addGrantType(new \OAuth2_GrantType_RefreshToken($storage));

		return $server;
	}

	public static function getDefaultScopes()
	{
		return 'basic';
	}

	public static function getSupportedScopes()
	{
		return array(
			'basic',
			'cursus',
			'groupes',
			'full',
			// same as basic but mandatory for openid
			'openid',
		);
	}

	public static function getItems($scopes = null)
	{
		if (!$scopes)
			$scopes = static::getDefaultScopes();

		$items = array();

		if (!is_array($scopes))
			$scopes = explode(' ', $scopes);

		foreach ($scopes as $scope)
		{
			if (in_array($scope, array('openid', 'basic', 'full')))
			{
				$items['basic'] = array(
					'fields' => array(
						'nom' => function ($as_no, &$data, $field) {
							// recup_info met en cache mémoire, tt va bien
							$infos = recup_info($as_no);
							$data['user'][$field] = $infos['nom'];
							return $infos['nom'];
						},
						'nomjf' => function ($as_no, &$data, $field) {
							// recup_info met en cache mémoire, tt va bien
							$infos = recup_info($as_no);
							$data['user'][$field] = $infos['nomjf'];
							return $infos['nomjf'];
						},
						'prenom' => function ($as_no, &$data, $field) {
							// recup_info met en cache mémoire, tt va bien
							$infos = recup_info($as_no);
							$data['user'][$field] = $infos['prenom'];
							return $infos['prenom'];
						},
						'photo' => function ($as_no, &$data, $field) {
							$photo = NA_check_photo($as_no);
							$photo = rawurlencode(\NA\Formatting::cleanUrl(\NAConst::get('URL_ROOT').$photo));
							$data['user'][$field] = $photo;
							return $photo;
						},
						'mail_contact' => function ($as_no, &$data, $field) {
							// recup_info met en cache mémoire, tt va bien
							$mail_contact = NA_recup_mail_prefere($as_no);
							$data['user'][$field] = $mail_contact;
							return $mail_contact;
						},
						'cotisant' => function ($as_no, &$data, $field) {
							// recup_info met en cache mémoire, tt va bien
							$infos = recup_info($as_no);
							$data['user'][$field] = $infos['cotisant'];
							return $infos['cotisant'];
						},
					),
					'description' =>
						function ($data) {
							return array(
								NA_FA("Utiliser votre nom, nom de famille et prénom"),
								NA_FA("Utiliser la photo de votre profil"),
								NA_FA("Utiliser l'email de contact lié à votre profil <br> (%value%)", array('value' => $data['user']['mail_contact'])),
								NA_FA("Utiliser le statut de votre cotisation"),
							);
						},
				);
			}

			if (in_array($scope, array('cursus', 'full')))
			{
				$items['cursus'] = array(
					'fields' => array(
						'promo' => function ($as_no, &$data, $field) {
							// recup_info met en cache mémoire, tt va bien
							$infos = recup_info($as_no);
							$data['cursus'][$field] = $infos['promo'];
							return $infos['promo'];
						},
					),
					'description' =>
						function ($data) {
							return array(
								NA_FA("Utiliser les informations sur votre cursus"),
							);
						},
				);
			}

			if (in_array($scope, array('groupes', 'full')))
			{
				$items['groupes'] = array(
					'fields' => array(
						'groupes' => function ($as_no, &$data, $field) {
							$groupes_as_no = \NA\Groupe\Groupe::recup_groupes_for_user($as_no);

							$groupes = array();

							if ($groupes_as_no)
							{
								foreach ($groupes_as_no as $item)
								{
									$groupe = array(
										'groupe' => $item['s_nom'],
										'role' => $GLOBALS['niveau_com1'][$item['details']],
									);

									$groupes[] = $groupe;
								}
							}
							$data['groupes'] = $groupes;
						},
					),
					'description' =>
						function ($data) {
							return array(
								NA_FA("Utiliser les informations sur vos appartenances aux groupes"),
							);
						},
				);
			}
		}

		return $items;
	}

	public static function getData($as_no, &$data, $scope = null)
	{
		$items = static::getItems($scope);

		if ($items)
		{
			foreach ($items as $item)
			{
				if ($item['fields'])
				{
					foreach ($item['fields'] as $field => $func_value)
					{
						if (is_callable($func_value))
							$func_value($as_no, $data, $field);
					}
				}
			}
		}
	}

	public static function authorize($params)
	{
		if (!class_exists('OAuth2_Request'))
		{
			require_once(REP_GLOBAL.'vendor/bshaffer/oauth2-server-php/src/OAuth2/Autoloader.php');
			\OAuth2_Autoloader::register();
		}

		$request = \OAuth2_Request::createFromGlobals();

		$scopes = $request->query('scope');
		if ($scopes)
		{
			$scopes = explode(' ', $scopes);
			foreach ($scopes as $scope)
			{
				if (!in_array($scope, static::getSupportedScopes()))
				{
					$response = new \OAuth2_Response();
					$response->setError(400, 'invalid_scope', "Scope: '" . $scope . "' not found");
					$response->send();
					exit;
				}
			}
		}

		if (!$_SESSION['utilisateur']->connecte)
		{
			$r = \NA\Router::get();
			$r->exec(array('controller' => 'Ep.Main', 'action' => 'index'));
			return;
		}
		else
		{
			$server = static::configureServer();
			$response = new \OAuth2_Response();

			$is_authorized = \NA\Ep\Models\Personne2Auth::getAuth($_SESSION['utilisateur']->as_no, $request->query('client_id'), $request->query('scope')) || isset($_POST['authorized']) ? true : false;

			// display an authorization form
			if (!$is_authorized && !isset($_POST['canceled']))
			{
				$data = array('request' => $request);
				$data['client_name'] = \NPDO::single_result("SELECT client_name FROM oauth_clients WHERE client_id = ?", array($request->query('client_id')));
				$data['items'] = static::getItems($scopes);

				$data['data'] = array();
				static::getData($_SESSION['utilisateur']->as_no, $data['data'], $request->query('scope'));

				foreach ($data['items'] as &$item)
				{
					$item['descriptions'] = $item['description']($data['data']);
				}

				$data['infos'] = recup_info($_SESSION['utilisateur']->as_no);
				$data['infos']['photo'] = NA_check_photo($_SESSION['utilisateur']->as_no);

				echo static::render('@cms/oauth2/authorize.html', $data);
				exit;
			}
			else
			{
				// validate the authorize request
				if (!$server->validateAuthorizeRequest($request, $response))
				{
					$response->send();
					die;
				}

				// print the authorization code if the user has authorized your client
				$server->handleAuthorizeRequest($request, $response, $is_authorized, $_SESSION['utilisateur']->as_no);

				if (!isset($_POST['canceled']))
				{
					$scope = $request->query('scope');
					if (!$scope)
						$scope = static::getDefaultScopes();
					\NA\Ep\Models\Personne2Auth::saveAuth($_SESSION['utilisateur']->as_no, $request->query('client_id'), $scope);

					// this is only here so that you get to see your code in the cURL request. Otherwise, we'd redirect back to the client
//					$code = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=') + 5);
//					exit("SUCCESS! Authorization Code: $code");

//					NA_print_r($response);
//					exit;
				}

				$response->send();
				exit;
			}
		}
	}

	public static function token($params)
	{
		$server = static::configureServer();

		//TODO si le code n'existe plus envoyer une erreur "l'autorisation a été révoquée par l'utilisateur

		// Handle a request for an OAuth2.0 Access Token and send the response to the client
		$server->handleTokenRequest(\OAuth2_Request::createFromGlobals(), new \OAuth2_Response())->send();
	}

	public static function profile($params)
	{
		$server = static::configureServer();
		$request = \OAuth2_Request::createFromGlobals();
		$response = new \OAuth2_Response();

		$token_data = $server->getAccessTokenData($request, $response);

		$supported_scopes = static::getSupportedScopes();
		$scopes = $request->request('scope');
		$scopes = array_filter(explode(' ', $scopes));

		if ($scopes)
		{
			foreach ($scopes as $scope)
			{
				if (!in_array($scope, $supported_scopes))
				{
					$response->setError(400, 'invalid_scope', "Scope: '" . $scope . "' not found");
					$response->send();
					exit;
				}
			}
		}

		if (!$scopes)
			$scopes = explode(' ', $token_data['scope']);

		// Pour vérifier si les scopes demandés sont bien gérés par le token
		if (!$server->verifyResourceRequest($request, $response, implode(' ', $scopes))) {
			// if the scope required is different from what the token allows, this will send a "401 insufficient_scope" error
			$response->send();
			exit;
		}

		$scopes_access = array();
		foreach ($scopes as $scope)
			$scopes_access[$scope] = $server->verifyResourceRequest($request, $response, $scope);

		$as_no = $token_data['user_id'];

		$data = array();
		static::getData($as_no, $data, array_keys(array_filter($scopes_access)));

		echo \NA\Formatting::utf8JsonEncode(array('success' => true, 'data' => $data));
	}

	public static function getAllRedirectURI()
	{
		$sql = "SELECT redirect_uri FROM oauth_clients WHERE redirect_uri != ''";
		$uri = \NPDO::tab_query_dim1($sql);
		return $uri;
	}

	public static function getAllowedURIs()
	{
		$sql = "SELECT allowed_urls FROM oauth_clients WHERE allowed_urls IS NOT NULL AND allowed_urls != ''";
		$URLs = \NPDO::tab_query_dim1($sql);

		$allowed = array();

		foreach ($URLs as $val)
		{
			$url = explode("\n", $val);
			$allowed = array_merge($allowed, $url);
		}

		return $allowed;
	}
}
