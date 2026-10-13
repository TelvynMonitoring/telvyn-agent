<?php
if (PHP_VERSION_ID < 80300) {
    error_log('[Telvyn] Instrumentation skipped: PHP 8.3 or newer is required.');
    return;
}
try {
    require __DIR__ . '/../vendor/autoload.php';
} catch (Throwable $error) {
    error_log('[Telvyn] Instrumentation could not start; application startup continues.');
}
