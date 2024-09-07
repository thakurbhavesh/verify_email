<?php
// Only handle POST requests
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['email'])) {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    header('Content-Type: application/json');

    // Initialize results array
    $results = [];

    // Step 1: Syntax Validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $results[] = ['step' => 'Syntax Validation', 'status' => 'danger', 'message' => 'Invalid email format.'];
        echo json_encode(['steps' => $results]);
        exit();
    } else {
        $results[] = ['step' => 'Syntax Validation', 'status' => 'success', 'message' => 'Valid email syntax: ' . $email];
    }

    // Extract the domain part from the email
    list($localPart, $domainPart) = explode('@', $email);

    // Step 2: DNS MX Lookup
    if (!checkdnsrr($domainPart, 'MX')) {
        if (!checkdnsrr($domainPart, 'A')) {
            $results[] = ['step' => 'DNS MX Lookup', 'status' => 'danger', 'message' => 'The domain does not have valid MX or A records.'];
            echo json_encode(['steps' => $results]);
            exit();
        } else {
            $results[] = ['step' => 'DNS MX Lookup', 'status' => 'success', 'message' => 'Valid A record found for ' . $domainPart];
        }
    } else {
        $results[] = ['step' => 'DNS MX Lookup', 'status' => 'success', 'message' => 'Valid MX records found for ' . $domainPart];
    }

    // Step 3: SMTP Server Connection
    $smtpValidation = validateSMTP($email, $domainPart);
    if ($smtpValidation['status'] == 'valid') {
        $results[] = ['step' => 'SMTP Server Connection', 'status' => 'success', 'message' => 'SMTP connection successful for ' . $domainPart];
    } else {
        $results[] = ['step' => 'SMTP Server Connection', 'status' => 'danger', 'message' => $smtpValidation['message']];
        echo json_encode(['steps' => $results]);
        exit();
    }

    // Step 4: Mailbox Validation
    $mailboxValidation = validateMailbox($email, $domainPart);
    if ($mailboxValidation['status'] == 'valid') {
        $results[] = ['step' => 'Mailbox Validation', 'status' => 'success', 'message' => 'Mailbox exists for ' . $email];
    } else {
        $results[] = ['step' => 'Mailbox Validation', 'status' => 'danger', 'message' => $mailboxValidation['message']];
    }

    // Step 5: Honeypot and Disposable Address Check
    $honeypotCheck = checkHoneypot($email);
    $disposableCheck = checkDisposable($email);
    if ($honeypotCheck) {
        $results[] = ['step' => 'Honeypot Check', 'status' => 'danger', 'message' => 'The email address is a known honeypot (spamtrap).'];
    } else {
        $results[] = ['step' => 'Honeypot Check', 'status' => 'success', 'message' => 'The email address is not a known honeypot.'];
    }

    if ($disposableCheck) {
        $results[] = ['step' => 'Disposable Address Check', 'status' => 'danger', 'message' => 'The email address is a known disposable address.'];
    } else {
        $results[] = ['step' => 'Disposable Address Check', 'status' => 'success', 'message' => 'The email address is not a known disposable address.'];
    }

    // Step 6: Catch-All Domain Check
    $catchAllCheck = checkCatchAll($domainPart);
    if ($catchAllCheck) {
        $results[] = ['step' => 'Catch-All Domain Check', 'status' => 'warning', 'message' => 'The domain is a catch-all domain.'];
    } else {
        $results[] = ['step' => 'Catch-All Domain Check', 'status' => 'success', 'message' => 'The domain is not a catch-all domain.'];
    }

    // Step 7: International Mailbox Support Check
    $internationalMailboxesCheck = checkInternationalMailboxes($domainPart);
    if ($internationalMailboxesCheck) {
        $results[] = ['step' => 'International Mailboxes Support Check', 'status' => 'danger', 'message' => 'The mail exchanger does not support international mailboxes.'];
    } else {
        $results[] = ['step' => 'International Mailboxes Support Check', 'status' => 'success', 'message' => 'The mail exchanger supports international mailboxes.'];
    }

    // Step 8: Temporary Unavailability Check
    $temporaryUnavailabilityCheck = checkTemporaryUnavailability($domainPart);
    if ($temporaryUnavailabilityCheck) {
        $results[] = ['step' => 'Temporary Unavailability Check', 'status' => 'warning', 'message' => 'The mail exchanger is temporarily unavailable.'];
    } else {
        $results[] = ['step' => 'Temporary Unavailability Check', 'status' => 'success', 'message' => 'The mail exchanger is available.'];
    }

    echo json_encode(['steps' => $results]);
}

// SMTP Validation Function
function validateSMTP($email, $domain) {
    $mxHosts = [];
    getmxrr($domain, $mxHosts);

    if (empty($mxHosts)) {
        $aRecord = gethostbyname($domain);
        if ($aRecord == $domain) {
            return ['status' => 'invalid', 'message' => "Failed to connect to A record of $domain."];
        }
        $mxHosts[] = $aRecord;
    }

    foreach ($mxHosts as $mxHost) {
        $connection = @fsockopen($mxHost, 25);
        if ($connection) {
            fclose($connection);
            return ['status' => 'valid', 'message' => "SMTP server is reachable for domain $domain."];
        }
    }
    return ['status' => 'invalid', 'message' => "Failed to connect to SMTP server for $domain."];
}

// Mailbox Validation Function
function validateMailbox($email, $domain) {
    $mxHosts = [];
    getmxrr($domain, $mxHosts);

    if (empty($mxHosts)) {
        $aRecord = gethostbyname($domain);
        if ($aRecord != $domain) {
            $mxHosts[] = $aRecord;
        }
    }

    foreach ($mxHosts as $mxHost) {
        $connection = @fsockopen($mxHost, 25, $errno, $errstr, 10);
        if (!$connection) {
            return ['status' => 'invalid', 'message' => "Could not connect to mail server: $errstr ($errno)"];
        }

        fgets($connection);
        fputs($connection, "HELO example.com\r\n");
        fgets($connection);
        fputs($connection, "MAIL FROM: <test@example.com>\r\n");
        fgets($connection);
        fputs($connection, "RCPT TO: <$email>\r\n");
        $response = fgets($connection);
        fputs($connection, "QUIT\r\n");
        fclose($connection);

        if (strpos($response, '250') !== false) {
            return ['status' => 'valid', 'message' => "Mailbox exists for $email."];
        } elseif (strpos($response, '550') !== false) {
            return ['status' => 'invalid', 'message' => "Mailbox not found for $email."];
        }
    }

    return ['status' => 'invalid', 'message' => "Failed to validate mailbox for $email."];
}

// Honeypot Check Function
function checkHoneypot($email) {
    $honeypotEmails = ['spamtrap@example.com', 'trap@spamtrap.com']; // Add more as needed
    return in_array($email, $honeypotEmails);
}

// Disposable Email Check Function
function checkDisposable($email) {
    $disposableDomains = ['mailinator.com', 'tempmail.com', '10minutemail.com']; // Add more as needed
    list(, $domain) = explode('@', $email);
    return in_array($domain, $disposableDomains);
}

// Catch-All Domain Check Function
function checkCatchAll($domain) {
    $testEmail = 'nonexistent' . time() . '@' . $domain;
    $mxHosts = [];
    getmxrr($domain, $mxHosts);

    foreach ($mxHosts as $mxHost) {
        $connection = @fsockopen($mxHost, 25, $errno, $errstr, 5);
        if ($connection) {
            fputs($connection, "HELO example.com\r\n");
            fgets($connection);
            fputs($connection, "MAIL FROM: <test@example.com>\r\n");
            fgets($connection);
            fputs($connection, "RCPT TO: <$testEmail>\r\n");
            $response = fgets($connection);
            fputs($connection, "QUIT\r\n");
            fclose($connection);

            if (strpos($response, '250') !== false) {
                return true; // Catch-all domain
            }
        }
    }
    return false; // Not a catch-all domain
}

// International Mailbox Support Check Function
function checkInternationalMailboxes($domain) {
    $testEmail = 'test@' . $domain;
    $mxHosts = [];
    getmxrr($domain, $mxHosts);

    foreach ($mxHosts as $mxHost) {
        $connection = @fsockopen($mxHost, 25, $errno, $errstr, 5);
        if ($connection) {
            fputs($connection, "HELO example.com\r\n");
            fgets($connection);
            fputs($connection, "MAIL FROM: <test@example.com>\r\n");
            fgets($connection);
            fputs($connection, "RCPT TO: <$testEmail>\r\n");
            $response = fgets($connection);
            fputs($connection, "QUIT\r\n");
            fclose($connection);

            if (strpos($response, '501') !== false) {
                return true; // Server does not support international mailboxes
            }
        }
    }
    return false; // Server supports international mailboxes
}

// Temporary Unavailability Check Function
function checkTemporaryUnavailability($domain) {
    $testEmail = 'test' . time() . '@' . $domain;
    $mxHosts = [];
    getmxrr($domain, $mxHosts);

    foreach ($mxHosts as $mxHost) {
        $connection = @fsockopen($mxHost, 25, $errno, $errstr, 5);
        if ($connection) {
            fputs($connection, "HELO example.com\r\n");
            fgets($connection);
            fputs($connection, "MAIL FROM: <test@example.com>\r\n");
            fgets($connection);
            fputs($connection, "RCPT TO: <$testEmail>\r\n");
            $response = fgets($connection);
            fputs($connection, "QUIT\r\n");
            fclose($connection);

            if (strpos($response, '421') !== false) {
                return true; // Temporary unavailability
            }
        }
    }
    return false; // Not temporarily unavailable
}
?>
