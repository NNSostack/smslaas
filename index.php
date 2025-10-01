<?php
// sms_verification.php
// Komplett eksempel: GatewayAPI + Google reCAPTCHA + logging + simpel rate-limit
// Dansk tekster/kommentarer

define("VERSION", "1.0");

$relativePath = "../c/" . $_GET["config"];
$absolutePath = __DIR__  . "/c/" . $_GET["config"];

$config = loadConfig("{$absolutePath}/config.json");

session_start();

/*
 * KONFIGURATION
 * - Anbefaling: sæt disse som miljøvariabler (f.eks. i Apache/Nginx eller .env), ikke i kode.
 */
define('GATEWAYAPI_TOKEN', getenv('GATEWAYAPI_TOKEN') ?: '983Q4HHfQ42bkfPjnMmGWfwQh06CP2Mf-9m5EpNoRgUFh7IHYYtp_C_rMyKcpLCN');
define('GATEWAYAPI_SENDER', getenv('GATEWAYAPI_SENDER') ?: 'SMSLaas'); // Afventer godkendelse i GatewayAPI dashboard
define('RECAPTCHA_SITE_KEY', getenv('RECAPTCHA_SITE_KEY') ?: '6Lf2edcrAAAAAM4dK2qe7-3Z_Ee5BixtGAVM64Bw');
define('RECAPTCHA_SECRET', getenv('RECAPTCHA_SECRET') ?: '6Lf2edcrAAAAAHE-2bWrNsd7W0zPoW69SEoEesU5');

/*
 * LOGGING: sti til logfil (relativ til denne fil). Sørg for at mappen eksisterer og er skrivbar.
 * Eksempel: chmod 700 logs && chown www-data:www-data logs
 */
define('LOG_DIR', __DIR__ . '/logs');
define('LOG_FILE', LOG_DIR . '/sms_send.log');

// Om vi logger den komplette kode eller kun maskerede (anbefalet: false i produktion)
define('LOG_FULL_CODE', false);

// Rate-limit indstillinger (simpel, session-baseret)
define('MAX_SENDS_PER_HOUR', 5);
define('COOLDOWN_SECONDS', 30);

// Hjælpefunktion: sikr at logmappe eksisterer
if (!is_dir(LOG_DIR)) {
    @mkdir(LOG_DIR, 0700, true);
}

/**
 * Simpel telefonvalidering: tillader + og 8-15 cifre.
 * Returnerer normaliseret nummer (kun + og digits) eller false.
 */
function validate_phone($phone) {
    $p = preg_replace('/[^\d\+]/', '', $phone);
    if (preg_match('/^\+?\d{8,15}$/', $p)) {
        return $p;
    }
    return false;
}

/**
 * Verificer Google reCAPTCHA (server-side).
 * Returnerer true/false.
 */
function verify_recaptcha($token, $secret) {
    if (empty($token) || empty($secret)) return false;
    $ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret' => $secret,
        'response' => $token
    ]));
    $resp = curl_exec($ch);
    curl_close($ch);
    if (!$resp) return false;
    $data = json_decode($resp, true);
    return ($data && isset($data['success']) && $data['success'] === true);
}

/**
 * Send SMS via GatewayAPI REST endpoint.
 * Returnerer assoc array med httpcode og response body.
 */
function send_sms_gatewayapi($to, $message) {
    $postfields = [
        "recipients" => [
            ["msisdn" => $to]
        ],
        "message" => $message,
        "sender" => GATEWAYAPI_SENDER
    ];

    $ch = curl_init('https://gatewayapi.eu/rest/mtsms');

curl_setopt_array($ch, [
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
  CURLOPT_USERPWD => GATEWAYAPI_TOKEN . ':',   // <- Basic Auth: token som username, tomt password
  CURLOPT_POST => true,
  CURLOPT_POSTFIELDS => json_encode($postfields, JSON_UNESCAPED_UNICODE),
]);


/*
    curl_setopt($ch, CURLOPT_URL, "https://gatewayapi.eu/rest/mtsms");
curl_setopt($ch,CURLOPT_HTTPHEADER, array("Content-Type: application/json"));
curl_setopt($ch,CURLOPT_USERPWD, $GATEWAYAPI_TOKEN.":");
curl_setopt($ch,CURLOPT_POSTFIELDS, json_encode($postfields));
curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
*/
//    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
//    curl_setopt($ch, CURLOPT_POST, true);
//    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($postfields));
//    curl_setopt($ch, CURLOPT_HTTPHEADER, [
//        "Content-Type: application/json",
//        "Authorization: Bearer " . GATEWAYAPI_TOKEN
//    ]);
    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return ['httpcode' => $httpcode, 'response' => $response];
}

/**
 * Log afsendelse til fil.
 * $data: associative array med felter vi ønsker at logge.
 *
 * Sikkerhed: vær påpasselig med hvad du logger. I produktion: overvej at kryptere/logge kun hash.
 */
function log_send(array $data) {
    $logfile = LOG_FILE;
    $ts = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s\Z'); // ISO8601 UTC
    // Standardfelter
    $entry = [
        'ts' => $ts,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'phone' => $data['phone'] ?? '',
        // hvis LOG_FULL_CODE === false, masker koden (behold sidste 2 cifre)
        'code' => (defined('LOG_FULL_CODE') && LOG_FULL_CODE && isset($data['code'])) ? $data['code'] :
                    (isset($data['code']) ? mask_code($data['code']) : ''),
        'httpcode' => $data['httpcode'] ?? '',
        'success' => isset($data['success']) ? ($data['success'] ? '1' : '0') : '',
        'response' => isset($data['response']) ? substr($data['response'], 0, 2000) : '' // begræns længde
    ];
    // Gem som JSON-enkodet linje (nemt at parse senere)
    $json = json_encode($entry, JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        // fallback til simple tekst
        $json = $ts . " - " . print_r($entry, true);
    }
    // Atomisk append med lås
    $fp = fopen($logfile, 'a');
    if ($fp) {
        flock($fp, LOCK_EX);
        fwrite($fp, $json . PHP_EOL);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        // Sørg for sikre rettigheder (gør kun hvis fil netop oprettet)
        @chmod($logfile, 0600);
    }
}

/**
 * Maskér kode: fx 123456 -> ****56
 */
function mask_code($code) {
    $c = (string)$code;
    $len = strlen($c);
    if ($len <= 2) return str_repeat('*', $len);
    $show = 2;
    return str_repeat('*', max(0, $len - $show)) . substr($c, -$show);
}

// Initialiser rate-limiter i session hvis ikke sat
if (!isset($_SESSION['send_tracker'])) {
    $_SESSION['send_tracker'] = [
        'count' => 0,
        'first_ts' => time(),
        'last_sent' => 0
    ];
}

// Håndter "send kode"-formular
$send_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'send_code') {
    $country_code = $_POST['country_code'] ?? '';
    $local_number = $_POST['phone'] ?? '';

    // Saml fuldt nummer
    $phone_raw = $country_code . $local_number;
    $recaptcha_token = $_POST['g-recaptcha-response'] ?? '';

    // Reset tæller hvis mere end 1 time siden første forsøg
    if (time() - $_SESSION['send_tracker']['first_ts'] > 3600) {
        $_SESSION['send_tracker']['count'] = 0;
        $_SESSION['send_tracker']['first_ts'] = time();
    }

    // cooldown mellem individuelle sendt
    $since_last = time() - $_SESSION['send_tracker']['last_sent'];
    if ($since_last < COOLDOWN_SECONDS) {
        $wait = COOLDOWN_SECONDS - $since_last;
        $send_message = "Vent venligst $wait sekunder før næste forsøg.";
    } elseif ($_SESSION['send_tracker']['count'] >= MAX_SENDS_PER_HOUR) {
        $send_message = "Grænsen for antal SMS-kald nået (" . MAX_SENDS_PER_HOUR . " pr. time). Prøv senere.";
    } else {
        // Valider telefon
        $phone = validate_phone($phone_raw);
        if (!$phone) {
            $send_message = "Ugyldigt telefonnummer. Brug fx +4512345678 eller internationalt format.";
        } else {
            // Verificer reCAPTCHA
            $okCaptcha = verify_recaptcha($recaptcha_token, RECAPTCHA_SECRET);
            if (!$okCaptcha) {
                $send_message = "reCAPTCHA verificering fejlede. Prøv venligst igen.";
            } else {
                // Generér sikker 6-cifret kode
                try {
                    $code = random_int(100000, 999999);
                } catch (Exception $e) {
                    $code = mt_rand(100000, 999999);
                }

                // Gem i session (til senere verifikation). Husk: sessions er ikke permanent storage.
                $_SESSION['verification'] = [
                    'phone' => $phone,
                    'code' => (string)$code,
                    'ts' => time(),
                    'attempts' => 0
                ];

                // Send SMS
                $messageText = "Din bekræftelseskode er: $code";
                $sendResult = send_sms_gatewayapi($phone, $messageText);

                $success = ($sendResult['httpcode'] >= 200 && $sendResult['httpcode'] < 300);

                // Log ALLE afsendelser (succes eller fejl). Hvis du kun vil logge succes, kan du betinge kaldet.
                log_send([
                    'phone' => $phone,
                    'code' => (string)$code,
                    'httpcode' => $sendResult['httpcode'],
                    'response' => $sendResult['response'],
                    'success' => $success
                ]);

                if ($success) {
                    $_SESSION['send_tracker']['count'] += 1;
                    $_SESSION['send_tracker']['last_sent'] = time();
                    $send_message = "Koden er sendt til $phone. Brug koden for at låse døren op.";
                } else {
                    $send_message = "Fejl ved afsendelse (kode: {$sendResult['httpcode']}). Respons: " . htmlspecialchars($sendResult['response']);
                }
            }
        }
    }
}

// Håndter "verificer kode"-formular
$verify_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'verify_code') {
    $input_code = trim($_POST['code'] ?? '');

    if (!isset($_SESSION['verification'])) {
        $verify_message = "Ingen kode fundet. Start forfra og anmod om en kode.";
    } else {
        // Begræns antal forsøg
        $_SESSION['verification']['attempts'] += 1;
        if ($_SESSION['verification']['attempts'] > 5) {
            unset($_SESSION['verification']);
            $verify_message = "For mange forkerte forsøg. Anmod om en ny kode.";
        } else {
            // Gyldighedstid (fx 10 minutter)
            if (time() - $_SESSION['verification']['ts'] > 600) {
                unset($_SESSION['verification']);
                $verify_message = "Koden er udløbet. Anmod om en ny kode.";
            } else {
                if (hash_equals($_SESSION['verification']['code'], $input_code)) {
                    $verified_phone = $_SESSION['verification']['phone'];
                    unset($_SESSION['verification']);
                    $verify_message = "Telefonnummer $verified_phone er bekræftet ✅";
                } else {
                    $verify_message = "Forkert kode. Forsøg " . $_SESSION['verification']['attempts'] . " af 5.";
                }
            }
        }
    }
}

function loadConfig($file) {
    if (!file_exists($file)) {
        return [];
    }

    $json = file_get_contents($file);
    $config = json_decode($json, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Error decoding JSON: " . json_last_error_msg());
    }

    return $config;
}

?>
<!doctype html>
<html lang="da">
<head>
    <meta charset="utf-8">
    <title>SMS Bekræftelse med CAPTCHA + Logging</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; max-width: 720px; }
        .logo { top: 10px; left: 10px; }
        .logo img { height: 120px;}
        form { margin-bottom: 1.5rem; padding: 0.5rem; border: 1px solid #ddd; border-radius: 8px; min-width: 300px; }
        label { display:block; margin-bottom: .3rem; }
        input[type="text"], input[type="tel"], input[type="number"] { padding: .5rem; width:100%; box-sizing: border-box; }
        button { padding: .6rem 1rem; margin-top: .6rem; }
        .msg { margin: .6rem 0; padding: .6rem; border-radius: 6px; }
        .msg.info { background:#eef; border:1px solid #cce; }
        .msg.error { background:#fee; border:1px solid #fbb; }
        .msg.success { background:#efe; border:1px solid #bfb; }
        small { color:#666; }
    </style>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <!-- Logo -->
    <div class="logo">
        <img src="<?php echo $relativePath; ?>/<?php echo $config["logo"] ?>" alt="Logo">
    </div>

    <?php if ($send_message): ?>
        <div class="msg <?php echo (stripos($send_message, 'fejl') !== false || stripos($send_message, 'ugyldigt') !== false) ? 'error' : 'info'; ?>">
            <?php echo htmlspecialchars($send_message); ?>
        </div>
    <?php endif; ?>

    <!-- FORM: SEND KODE -->
<form method="post" novalidate>
    <input type="hidden" name="action" value="send_code">

    <label for="country_code">Land</label>
    <select id="country_code" name="country_code" required>
        <option value="+45">Danmark (+45)</option>
        <option value="+49">Tyskland (+49)</option>
        <option value="+47">Norge (+47)</option>
        <option value="+46">Sverige (+46)</option>
        <option value="+44">England (+44)</option>
        <option value="+354">Island (+354)</option>
        <option value="+298">Færøerne (+298)</option>
        <option value="+48">Polen (+48)</option>
        <option value="+31">Holland (+31)</option>
        <option value="+33">Frankrig (+33)</option>
        <option value="+39">Italien (+39)</option>
    </select>

    <label for="phone">Telefonnummer (uden landekode)</label>
    <input type="tel" id="phone" name="phone" placeholder="12345678" required>

    <div style="margin-top:.6rem;" class="g-recaptcha" data-sitekey="<?php echo RECAPTCHA_SITE_KEY; ?>"></div>

    <button type="submit">Send bekræftelseskode via SMS</button>
</form>

    <!-- FORM: INDTAST KODE -->
   <!-- <form method="post" novalidate>
       <input type="hidden" name="action" value="verify_code">
       <label for="code">Indtast 6-cifret kode</label>
       <input type="text" id="code" name="code" pattern="\d{6}" placeholder="123456" required>
       <button type="submit">Bekræft kode</button>
    </form>

    <?php if ($verify_message): ?>
        <div class="msg <?php echo (stripos($verify_message, 'bekræftet') !== false) ? 'success' : 'error'; ?>">
            <?php echo htmlspecialchars($verify_message); ?>
        </div>
    <?php endif; ?>
    -->
    <hr>
    <p>Velkommen til <?php echo $config["customerName"][0] ?>. Indtast dit telefonnummer og få en SMS med koden til døren</p>
    <p>Willkommen zu <?php echo $config["customerName"][1] ?>. Bitte geben Sie ihre Telefonummer ein, und Sie bekommen eine Text mit dem Kode für die Tür.</p>
    <p>Welcome to <?php echo $config["customerName"][2] ?>. Write your Telephonenumber and you get a code for the door.</p>
    <h6><?php echo $config["customerName"][0] ?><br/><?php echo $config["address"] ?><br/><?php echo $config["phone"] ?></br>Powered by SMSLås. Version <?php echo VERSION ?></h6>
</body>
</html>
