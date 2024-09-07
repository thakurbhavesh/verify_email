<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .verification-step {
            margin-top: 20px;
        }
        .progress-container {
            margin-top: 20px;
            display: none;
        }
        .result-message {
            margin-top: 10px;
        }
        label{
            font-weight:bold;
        }
    </style>
</head>
<body>

<div class="container mt-5">
    <div class="card shadow-sm">
        <div class="card-header">
            <h3 class="card-title">Email Verification Form</h3>
        </div>
        <div class="card-body">
            <form id="emailForm">
                <div class="mb-3">
                    <label for="email" class="form-label">Enter Email Address:</label>
                    <input type="email" class="form-control" id="email" name="email" placeholder="Enter email" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Verify Email</button>
            </form>

            <!-- Progress Bar -->
            <div class="progress-container">
                <div class="progress">
                    <div class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%;" id="progressBar"></div>
                </div>
            </div>

            <!-- Verification Results -->
            <div id="verificationResults" class="verification-step"></div>
        </div>
    </div>
</div>

<script>
document.getElementById('emailForm').addEventListener('submit', function(e) {
    e.preventDefault(); // Prevent the default form submission
    const email = document.getElementById('email').value;
    const resultDiv = document.getElementById('verificationResults');
    const progressBar = document.getElementById('progressBar');
    const progressContainer = document.querySelector('.progress-container');

    resultDiv.innerHTML = '';  // Clear previous results
    progressBar.style.width = '0%';  // Reset progress bar
    progressContainer.style.display = 'block'; // Show progress bar

    // Send the email to the server via AJAX
    fetch('email_verify_ajax.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'email=' + encodeURIComponent(email)
    })
    .then(response => response.json())
    .then(data => {
        progressBar.style.width = '100%'; // Complete the progress bar
        resultDiv.innerHTML = '';  // Clear previous results

        // Display each step's result as they come in
        data.steps.forEach(step => {
            const stepDiv = document.createElement('div');
            stepDiv.classList.add('alert', step.status === 'success' ? 'alert-success' : 'alert-danger', 'result-message');
            stepDiv.innerHTML = `<strong>${step.step}:</strong> ${step.message}`;
            resultDiv.appendChild(stepDiv);
        });
    })
    .catch(error => {
        progressBar.style.width = '100%'; // Complete the progress bar
        resultDiv.innerHTML = '<p class="alert alert-danger">Error: ' + error.message + '</p>';
    });
});
</script>

</body>
</html>
