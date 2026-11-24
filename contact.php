<?php
// Contact form handler for abstractimplements.tech
// Receives the POST from the form on index.html and emails it to $TO.
// Replies with JSON: {"ok": true} or {"ok": false, "error": "..."}.

declare(strict_types=1);

$TO   = 'info@abstractimplements.tech';
// Must be a mailbox on this domain, or the message is likely to be rejected or marked as spam.
$FROM = 'tye@abstractimplements.tech';

$TOPICS = [
    'choosing' => 'Choosing a platform or stack',
    'strategy' => 'Strategy & architecture',
    'cloud'    => 'Cloud & infrastructure',
    'software' => 'Software delivery',
    'data'     => 'Data & AI',
    'training' => 'Training & mentoring',
    'other'    => 'Something else',
];

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

$headers = [
    'From: Abstract Implements website <' . $FROM . '>',
    'Reply-To: ' . $email,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
];

$sent = mail(
    $TO,
    '=?UTF-8?B?' . base64_encode($subject) . '?=',
    $body,
    implode("\r\n", $headers),
    '-f' . $FROM
);

if (!$sent) {
    respond(500, ['ok' => false, 'error' => 'The message could not be sent.']);
}

respond(200, ['ok' => true]);
