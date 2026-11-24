<?php
// Contact form handler for abstractimplements.tech
// Receives the POST from the form on index.html and emails it to $TO,
// sending through the mailbox's own SMTP server so the message is authenticated.
// Replies with JSON: {"ok": true} or {"ok": false, "error": "..."}.

declare(strict_types=1);

$TO   = 'info@abstractimplements.tech';

$TOPICS = [
    'choosing' => 'Choosing a platform or stack',
    'strategy' => 'Strategy & architecture',
    'cloud'    => 'Cloud & infrastructure',
    'software' => 'Software delivery',
    'data'     => 'Data & AI',
    'training' => 'Training & mentoring',
    'other'    => 'Something else',
];

// SMTP settings live in contact-config.php, which is NOT in git.
// Preferred location: one level above the web root. Fallback: next to this file.
$CONFIG = null;
foreach ([dirname(__DIR__) . '/contact-config.php', __DIR__ . '/contact-config.php'] as $path) {
    if (is_file($path)) {
        $CONFIG = require $path;
        break;
    }
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respond(int $status, array $body): void
{
    http_response_code($status);
    echo json_encode($body);
    exit;
}

// One line of text: trimmed, no control characters (blocks email header injection), length-capped.
function clean_line(string $value, int $max): string
{
    $value = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value) ?? '';
    return mb_substr(trim($value), 0, $max);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(405, ['ok' => false, 'error' => 'Method not allowed']);
}

// Honeypot: real visitors never see or fill this field. Pretend success so bots move on.
if (trim((string)($_POST['website'] ?? '')) !== '') {
    respond(200, ['ok' => true]);
}

$name    = clean_line((string)($_POST['name'] ?? ''), 120);
$email   = clean_line((string)($_POST['email'] ?? ''), 200);
$company = clean_line((string)($_POST['company'] ?? ''), 160);
$topic   = (string)($_POST['topic'] ?? 'other');
$message = trim(mb_substr((string)($_POST['message'] ?? ''), 0, 5000));

if ($name === '' || $message === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    respond(422, ['ok' => false, 'error' => 'Please fill in your name, a valid email address and a message.']);
}

$topicLabel = $TOPICS[$topic] ?? $TOPICS['other'];

$subject = 'Website enquiry: ' . $topicLabel . ' (' . $name . ')';
$body = "Name: $name\n"
      . "Email: $email\n"
      . 'Company: ' . ($company !== '' ? $company : '-') . "\n"
      . "Topic: $topicLabel\n"
      . "\n"
      . str_replace(["\r\n", "\r"], "\n", $message) . "\n"
      . "\n-- \nSent from the contact form on abstractimplements.tech\n";

if (!is_array($CONFIG) || empty($CONFIG['username']) || empty($CONFIG['password'])) {
    error_log('contact.php: contact-config.php is missing or incomplete');
    respond(500, ['ok' => false, 'error' => 'The message could not be sent.']);
}

$FROM = (string)($CONFIG['from'] ?? $CONFIG['username']);

// Reads one SMTP reply (which may span several lines) and checks its status code.
function smtp_expect($socket, int $code): void
{
    $reply = '';
    while (($line = fgets($socket, 1024)) !== false) {
        $reply .= $line;
        if (strlen($line) < 4 || $line[3] === ' ') {
            break;
        }
    }
    if ((int)substr($reply, 0, 3) !== $code) {
        throw new RuntimeException('SMTP expected ' . $code . ', got: ' . trim($reply));
    }
}

function smtp_command($socket, string $command, int $code): void
{
    fwrite($socket, $command . "\r\n");
    smtp_expect($socket, $code);
}

// Sends one plain-text message over an authenticated, encrypted SMTP connection.
function smtp_send(array $config, string $from, string $to, string $replyTo, string $subject, string $body): void
{
    $host = (string)($config['host'] ?? 'smtp.hostinger.com');
    $protocol = (string)($config['protocol'] ?? 'ssl');
    $port = (int)($config['port'] ?? ($protocol === 'tls' ? 587 : 465));

    $socket = stream_socket_client(($protocol === 'tls' ? 'tls' : 'ssl') . '://' . $host . ':' . $port, $errno, $errstr, 15);
    if ($socket === false) {
        throw new RuntimeException('SMTP connect failed: ' . $errstr);
    }
    stream_set_timeout($socket, 15);

    try {
        smtp_expect($socket, 220);
        smtp_command($socket, 'EHLO abstractimplements.tech', 250);
        smtp_command($socket, 'AUTH LOGIN', 334);
        smtp_command($socket, base64_encode((string)$config['username']), 334);
        smtp_command($socket, base64_encode((string)$config['password']), 235);
        smtp_command($socket, 'MAIL FROM:<' . $from . '>', 250);
        smtp_command($socket, 'RCPT TO:<' . $to . '>', 250);
        smtp_command($socket, 'DATA', 354);

        $headers = [
            'Date: ' . date('r'),
            'Message-ID: <' . bin2hex(random_bytes(16)) . '@abstractimplements.tech>',
            'From: Abstract Implements website <' . $from . '>',
            'To: <' . $to . '>',
            'Reply-To: <' . $replyTo . '>',
            'Subject: ' . (preg_match('/[^\x20-\x7E]/', $subject) ? '=?UTF-8?B?' . base64_encode($subject) . '?=' : $subject),
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: quoted-printable',
        ];
        // Quoted-printable keeps plain text readable on the wire (base64 bodies raise spam scores).
        // A leading dot on a line is doubled, as SMTP requires.
        $encoded = quoted_printable_encode(str_replace("\n", "\r\n", $body));
        $encoded = preg_replace('/^\./m', '..', $encoded);
        $data = implode("\r\n", $headers) . "\r\n\r\n" . rtrim($encoded, "\r\n") . "\r\n";

        fwrite($socket, $data . ".\r\n");
        smtp_expect($socket, 250);
        fwrite($socket, "QUIT\r\n");
    } finally {
        fclose($socket);
    }
}

try {
    smtp_send($CONFIG, $FROM, $TO, $email, $subject, $body);
} catch (Throwable $e) {
    error_log('contact.php: ' . $e->getMessage());
    respond(500, ['ok' => false, 'error' => 'The message could not be sent.']);
}

respond(200, ['ok' => true]);
