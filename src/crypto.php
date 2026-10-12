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

function issue_reset_token(string $email): string
{
    // Unpredictable, high-entropy token. It is NOT derived from the email or the
    // date, so it cannot be recomputed by anyone who merely knows the address.
    $token = bin2hex(random_bytes(32));
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    if ($token === "") {
        return false;
    }
    $pdo = db();
    $row = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $row->execute([$email]);
    $stored = $row->fetch();
    // A token must actually have been issued for this address.
    if (!$stored) {
        return false;
    }
    // Same-day expiry, matching the notice the app shows ("Tokens expire at the
    // end of the calendar day").
    if (substr((string)$stored["created_at"], 0, 10) !== gmdate("Y-m-d")) {
        return false;
    }
    if (!hash_equals((string)$stored["token"], $token)) {
        return false;
    }
    // One-time use: burn the token so a captured value cannot be replayed.
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return true;
}
