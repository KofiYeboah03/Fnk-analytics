<?php
// refresh_session.php - Session refresh handler
require_once 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Not logged in']);
    exit;
}

try {
    $pdo = getDBConnection();
    
    // Check if session token exists and is valid
    if (isset($_SESSION['session_token'])) {
        $stmt = $pdo->prepare("SELECT id, expires_at FROM user_sessions WHERE session_token = ? AND user_id = ?");
        $stmt->execute([$_SESSION['session_token'], $_SESSION['user_id']]);
        $session = $stmt->fetch();
        
        if (!$session || strtotime($session['expires_at']) < time()) {
            // Session expired
            session_destroy();
            echo json_encode(['success' => false, 'message' => 'Session expired']);
            exit;
        }
        
        // Extend session expiration
        $newExpiresAt = date('Y-m-d H:i:s', time() + SESSION_LIFETIME);
        $stmt = $pdo->prepare("UPDATE user_sessions SET expires_at = ? WHERE id = ?");
        $stmt->execute([$newExpiresAt, $session['id']]);
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Session refreshed'
    ]);
    
} catch (Exception $e) {
    error_log("Session refresh error: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'message' => 'Session refresh failed'
    ]);
}
?>