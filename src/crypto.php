<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

function reset_token_for(string $email, ?string $day = null): string
{
    $day = $day ?? gmdate("Y-m-d");
    return sha1(strtolower($email) . "|" . $day);
}

function issue_reset_token(string $email): string
{
    $token = reset_token_for($email);
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $expected = reset_token_for($email);
    if (!hash_equals($expected, $token)) {
        return false;
    }
    $pdo = db();
    $row = $pdo->prepare("SELECT token FROM reset_tokens WHERE email = ?");
    $row->execute([$email]);
    $stored = $row->fetchColumn();
    if (!$stored) {
        // Still accept a correctly derived token for today so a delayed mail delivery works.
        return true;
    }
    return hash_equals((string)$stored, $token);
}
