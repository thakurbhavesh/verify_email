<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification with Confetti</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f0f0f0;
            position: relative;
            overflow: hidden;
        }
        .container {
            text-align: center;
            z-index: 1;
        }
        form {
            margin-bottom: 20px;
        }
        input[type="email"] {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            width: 300px;
        }
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            background: #007bff;
            color: white;
            cursor: pointer;
        }
        button:hover {
            background: #0056b3;
        }
        .loader {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .result {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Check Email Mailbox</h1>
        <form id="emailForm" method="POST">
            <input type="email" name="email" id="email" required placeholder="Enter email address">
            <button type="submit">Check</button>
        </form>
        <div id="loader" class="loader" style="display: none;"></div>
        <div id="result" class="result"></div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/@tsparticles/confetti@3.0.3/tsparticles.confetti.bundle.min.js"></script>
    <script>
        document.getElementById('emailForm').addEventListener('submit', function(event) {
            event.preventDefault();
            
            const email = document.getElementById('email').value;
            const loader = document.getElementById('loader');
            const result = document.getElementById('result');
            
            loader.style.display = 'block';
            result.innerHTML = '';

            fetch('', {
                method: 'POST',
                body: new URLSearchParams('email=' + email),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            })
            .then(response => response.text())
            .then(data => {
                loader.style.display = 'none';
                result.innerHTML = data;

                // Check if email is valid to trigger confetti
                if (data.includes("valid and active")) {
                    celebrate();
                }
            })
            .catch(error => {
                loader.style.display = 'none';
                result.innerHTML = 'An error occurred. Please try again.';
            });
        });

        function celebrate() {
            const duration = 15 * 1000;
            const animationEnd = Date.now() + duration;
            let skew = 1;

            function randomInRange(min, max) {
                return Math.random() * (max - min) + min;
            }

            (function frame() {
                const timeLeft = animationEnd - Date.now();
                const ticks = Math.max(200, 500 * (timeLeft / duration));

                skew = Math.max(0.8, skew - 0.001);

                confetti({
                    particleCount: 1,
                    startVelocity: 0,
                    ticks: ticks,
                    origin: {
                        x: Math.random(),
                        y: Math.random() * skew - 0.2,
                    },
                    colors: ["#ffffff", "#ffcc00", "#ff6699", "#66ccff"],
                    shapes: ["circle"],
                    gravity: randomInRange(0.4, 0.6),
                    scalar: randomInRange(0.4, 1),
                    drift: randomInRange(-0.4, 0.4),
                });

                if (timeLeft > 0) {
                    requestAnimationFrame(frame);
                }
            })();
        }
    </script>

    <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        function verifyEmailSMTP($email)
        {
            $domain = substr(strrchr($email, "@"), 1);

            // Check for valid MX records (Mail Exchange server)
            if (!checkdnsrr($domain, 'MX')) {
                return "No MX records found for the domain.";
            }

            // Get MX records
            getmxrr($domain, $mxhosts);
            $mxHost = $mxhosts[0];  // Choose the first MX record

            // Connect to the mail server on port 25
            $connection = fsockopen($mxHost, 25, $errno, $errstr, 10);
            if (!$connection) {
                return "Failed to connect to the mail server: $errstr ($errno)";
            }

            // Start SMTP handshake
            $response = fgets($connection, 512);
            fwrite($connection, "HELO example.com\r\n");
            $response = fgets($connection, 512);

            // Define sender (fake email for testing purposes)
            fwrite($connection, "MAIL FROM: <test@example.com>\r\n");
            $response = fgets($connection, 512);

            // Define recipient (the email you are checking)
            fwrite($connection, "RCPT TO: <$email>\r\n");
            $response = fgets($connection, 512);

            // Analyze the server response
            if (strpos($response, "250") !== false) {
                fclose($connection);
                return "Email is valid and active! ✅";
            } elseif (strpos($response, "550") !== false || strpos($response, "554") !== false) {
                fclose($connection);
                return "Email address is invalid or inactive. ❌";
            } else {
                fclose($connection);
                return "Unknown response from mail server: $response";
            }
        }

        // Get the email from POST request
        $email = $_POST['email'];
        echo '<script>document.getElementById("result").innerHTML = "' . addslashes(verifyEmailSMTP($email)) . '";</script>';
    }
    ?>
</body>
</html>
