<?php
// 设置会话cookie有效期为30天，并启用安全标志
session_set_cookie_params([
    'lifetime' => 30 * 24 * 3600,
    'path' => '/',
    'domain' => '',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

// 生成CSRF令牌
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
require_once 'db_connect.php';
require_once 'lib/Parsedown.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// 获取当前用户信息
$mysqli = get_db_connection();
$stmt = $mysqli->prepare("SELECT username, avatar FROM users WHERE id = ?");
$stmt->bind_param("i", $_SESSION['user_id']);
$stmt->execute();
$result = $stmt->get_result();
$current_user = $result->fetch_assoc();
$stmt->close();

// 设置session username
$_SESSION['username'] = $current_user['username'];

// 如果用户没有头像，设置默认头像（使用数据URI避免文件依赖）
if (empty($current_user['avatar'])) {
    $current_user['avatar'] = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"%3E%3Ccircle cx="50" cy="50" r="50" fill="%23e2e8f0"/%3E%3Ccircle cx="50" cy="35" r="18" fill="%2394a3b8"/%3E%3Cpath d="M 20 85 Q 20 60 50 60 Q 80 60 80 85 Z" fill="%2394a3b8"/%3E%3C/svg%3E';
}

$config = require 'config.php';
$parsedown = new Parsedown();
$parsedown->setSafeMode(true);

// Custom parse function - 已移除HTML块功能以防止XSS攻击
function customParse($text, $parsedown)
{
    // 移除控制字符
    $text = preg_replace('/[\x00-\x1F\x7F]/u', '', $text);
    
    // 只使用Parsedown的安全模式渲染Markdown
    return $parsedown->text($text);
}

// 记录访问日志
function logAccess($message)
{
    global $config;
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $logEntry = "[$timestamp] IP: $ip | $message | User-Agent: $userAgent\n";
    file_put_contents($config['log_file'], $logEntry, FILE_APPEND | LOCK_EX);
}

// 获取用户IP
function getUserIP()
{
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

// 检查发送频率限制
function checkRateLimit($user_id)
{
    global $config;
    $rateFile = "data/rate_$user_id.json";
    $now = time();

    if (file_exists($rateFile)) {
        $rateData = json_decode(file_get_contents($rateFile), true);
        $rateData = array_filter($rateData, function ($timestamp) use ($now) {
            return ($now - $timestamp) < 60;
        });

        if (count($rateData) >= $config['rate_limit']) {
            return false;
        }
    } else {
        $rateData = [];
    }

    $rateData[] = $now;
    file_put_contents($rateFile, json_encode($rateData), LOCK_EX);
    return true;
}

// 清理旧的频率限制文件
function cleanOldRateFiles()
{
    $files = glob('data/rate_*.json');
    $now = time();
    foreach ($files as $file) {
        if ($now - filemtime($file) > 3600) {
            unlink($file);
        }
    }
}

// 获取用户列表
function getUserList()
{
    $mysqli = get_db_connection();
    $stmt = $mysqli->prepare("SELECT id, username, avatar FROM users WHERE id != ?");
    $stmt->bind_param("i", $_SESSION['user_id']);
    $stmt->execute();
    $result = $stmt->get_result();
    $users = [];
    while ($row = $result->fetch_assoc()) {
        // 设置默认头像（使用数据URI避免文件依赖）
        if (empty($row['avatar'])) {
            $row['avatar'] = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"%3E%3Ccircle cx="50" cy="50" r="50" fill="%23e2e8f0"/%3E%3Ccircle cx="50" cy="35" r="18" fill="%2394a3b8"/%3E%3Cpath d="M 20 85 Q 20 60 50 60 Q 80 60 80 85 Z" fill="%2394a3b8"/%3E%3C/svg%3E';
        }
        $users[] = $row;
    }
    $stmt->close();
    $mysqli->close();
    return $users;
}

// 获取用户设置
function getUserSettings($user_id)
{
    // 验证用户ID
    if (!is_numeric($user_id) || $user_id <= 0) {
        return ['theme' => 0, 'radius' => 20];
    }
    $user_id = intval($user_id);
    
    $settingsFile = "data/settings_$user_id.json";
    
    // 确保文件在data目录内
    $realPath = realpath(dirname($settingsFile));
    $dataPath = realpath('data');
    if ($realPath === false || $dataPath === false || $realPath !== $dataPath) {
        return ['theme' => 0, 'radius' => 20];
    }
    
    if (file_exists($settingsFile)) {
        $content = file_get_contents($settingsFile);
        $settings = json_decode($content, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($settings)) {
            return $settings;
        }
    }
    return ['theme' => 0, 'radius' => 20]; // 默认设置
}

// 保存用户设置
function saveUserSettings($user_id, $settings)
{
    // 验证用户ID
    if (!is_numeric($user_id) || $user_id <= 0) {
        return false;
    }
    $user_id = intval($user_id);
    
    // 验证设置数据
    if (!is_array($settings)) {
        return false;
    }
    
    $settingsFile = "data/settings_$user_id.json";
    
    // 确保文件在data目录内
    $realPath = realpath(dirname($settingsFile));
    $dataPath = realpath('data');
    if ($realPath === false || $dataPath === false || $realPath !== $dataPath) {
        return false;
    }
    
    return file_put_contents($settingsFile, json_encode($settings), LOCK_EX) !== false;
}

// 处理AJAX请求
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    // 验证CSRF令牌
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Invalid CSRF token']);
        exit;
    }

    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'update_profile':
            // ... (Code for updating profile, unchanged)
            $username = $_POST['username'] ?? $current_user['username'];
            $avatar_path = $current_user['avatar'];
            $mysqli = get_db_connection();
            $success = false;

            if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
                $file = $_FILES['avatar'];
                
                // 验证文件是否为真实图片
                $imageInfo = @getimagesize($file['tmp_name']);
                if ($imageInfo === false) {
                    echo json_encode(['success' => false, 'message' => '无效的图片文件']);
                    exit;
                }
                
                // 验证真实MIME类型
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mimeType = finfo_file($finfo, $file['tmp_name']);
                finfo_close($finfo);
                
                $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
                if (!in_array($mimeType, $allowed_types)) {
                    echo json_encode(['success' => false, 'message' => '不支持的图片格式']);
                    exit;
                }
                
                // 验证文件大小
                if ($file['size'] > 2 * 1024 * 1024) {
                    echo json_encode(['success' => false, 'message' => '图片文件过大']);
                    exit;
                }
                
                // 使用安全的文件名
                $ext = image_type_to_extension($imageInfo[2], false);
                $new_file_name = bin2hex(random_bytes(16)) . '.' . $ext;
                $upload_dir = 'avatars/';
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }
                $new_path = $upload_dir . $new_file_name;

                if (move_uploaded_file($file['tmp_name'], $new_path)) {
                    $avatar_path = $new_path;
                    // 删除旧头像文件（如果不是默认头像且文件存在）
                    if ($current_user['avatar'] !== 'default_avatar.png' &&
                        !str_starts_with($current_user['avatar'], 'data:image/') &&
                        file_exists($current_user['avatar'])) {
                        unlink($current_user['avatar']);
                    }
                } else {
                    echo json_encode(['success' => false, 'message' => '头像上传失败']);
                    exit;
                }
            }

            $stmt = $mysqli->prepare("UPDATE users SET username = ?, avatar = ? WHERE id = ?");
            $stmt->bind_param("ssi", $username, $avatar_path, $_SESSION['user_id']);

            if ($stmt->execute()) {
                $_SESSION['username'] = $username;
                logAccess("User profile updated by {$_SESSION['username']}");
                echo json_encode(['success' => true, 'message' => '个人信息更新成功', 'new_username' => $username, 'new_avatar' => $avatar_path]);
            } else {
                error_log("Profile update failed: " . $mysqli->error);
                echo json_encode(['success' => false, 'message' => '更新失败: ' . $mysqli->error]);
            }
            $stmt->close();
            $mysqli->close();
            break;
        case 'send_message':
            if (!checkRateLimit($_SESSION['user_id'])) {
                echo json_encode(['success' => false, 'message' => '发送太频繁，请稍后再试']);
                exit;
            }

            $message = trim($_POST['message'] ?? '');
            $replyTo = trim($_POST['reply_to'] ?? '');
            
            // 移除控制字符
            $message = preg_replace('/[\x00-\x1F\x7F]/u', '', $message);

            if (empty($message)) {
                echo json_encode(['success' => false, 'message' => '消息内容不能为空']);
                exit;
            }

            if (strlen($message) > $config['message_max_length']) {
                echo json_encode(['success' => false, 'message' => '消息长度不能超过' . $config['message_max_length'] . '个字符']);
                exit;
            }

            $messages = json_decode(file_get_contents($config['db_file']), true) ?: [];

            $replyToData = null;
            if ($replyTo) {
                $found = false;
                foreach ($messages as $msg) {
                    if ($msg['id'] === $replyTo && !$msg['recalled']) {
                        $replyToData = [
                            'id' => $replyTo,
                            'username' => $msg['username'],
                            'avatar' => $msg['avatar'],
                            'message' => $msg['message']
                        ];
                        $found = true;
                        break;
                    }
                }
            }

            $newMessage = [
                'id' => uniqid(),
                'user_id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'],
                'avatar' => $current_user['avatar'],
                'message' => $message,
                'reply_to' => $replyToData,
                'timestamp' => time(),
                'ip' => getUserIP(),
                'recalled' => false
            ];

            array_unshift($messages, $newMessage);

            if (count($messages) > $config['max_messages']) {
                $messages = array_slice($messages, 0, $config['max_messages']);
            }

            file_put_contents($config['db_file'], json_encode($messages, JSON_UNESCAPED_UNICODE), LOCK_EX);

            $newMessage['message'] = customParse($message, $parsedown);
            if ($replyToData) {
                $newMessage['reply_to']['message'] = customParse($replyToData['message'], $parsedown);
            }

            logAccess("Message sent by {$_SESSION['username']}");
            echo json_encode(['success' => true, 'message' => '消息发送成功', 'new_message' => $newMessage]);
            break;

        case 'get_messages':
            // ... (Code with fix for recalled messages, unchanged)
            if (!file_exists($config['db_file'])) {
                echo json_encode(['success' => false, 'message' => '消息文件不存在']);
                exit;
            }
            $messages = json_decode(file_get_contents($config['db_file']), true) ?: [];

            $unrecalled_messages = array_filter($messages, function($msg) {
                return !($msg['recalled'] ?? false);
            });
            
            $parsedMessages = [];
            foreach ($unrecalled_messages as $msg) {
                $msg['message'] = customParse($msg['message'], $parsedown);
                if ($msg['reply_to']) {
                    $msg['reply_to']['message'] = customParse($msg['reply_to']['message'], $parsedown);
                }
                $parsedMessages[] = $msg;
            }
            usort($parsedMessages, function ($a, $b) {
                return $b['timestamp'] - $a['timestamp'];
            });
            echo json_encode(['success' => true, 'messages' => $parsedMessages]);
            break;

        case 'send_private_message':
            // ... (Code for sending private message, unchanged)
            $receiver_id = intval($_POST['receiver_id'] ?? 0);
            $message = trim($_POST['private_message'] ?? '');
            $replyToId = !empty($_POST['reply_to']) ? intval($_POST['reply_to']) : null;
            
            // 移除控制字符
            $message = preg_replace('/[\x00-\x1F\x7F]/u', '', $message);

            if (empty($message)) {
                echo json_encode(['success' => false, 'message' => '消息内容不能为空']);
                exit;
            }
            if ($receiver_id <= 0) {
                echo json_encode(['success' => false, 'message' => '请选择接收者']);
                exit;
            }

            if (!checkRateLimit($_SESSION['user_id'])) {
                echo json_encode(['success' => false, 'message' => '发送太频繁，请稍后再试']);
                exit;
            }

            $mysqli = get_db_connection();
            if ($replyToId !== null) {
                $stmt = $mysqli->prepare("SELECT id FROM private_messages WHERE id = ? AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))");
                $stmt->bind_param("iiiii", $replyToId, $_SESSION['user_id'], $receiver_id, $receiver_id, $_SESSION['user_id']);
                $stmt->execute();
                if ($stmt->get_result()->num_rows === 0) {
                    $replyToId = null;
                }
                $stmt->close();
            }

            $stmt = $mysqli->prepare("INSERT INTO private_messages (sender_id, receiver_id, message, reply_to_id, timestamp, recalled) VALUES (?, ?, ?, ?, NOW(), FALSE)");
            $stmt->bind_param("iisi", $_SESSION['user_id'], $receiver_id, $message, $replyToId);

            if ($stmt->execute()) {
                $messageId = $mysqli->insert_id;
                $stmt->close();
                $stmt = $mysqli->prepare("
                    SELECT pm.*, u1.username as sender_username, u1.avatar as sender_avatar, u2.username as receiver_username
                    FROM private_messages pm
                    JOIN users u1 ON pm.sender_id = u1.id
                    JOIN users u2 ON pm.receiver_id = u2.id
                    WHERE pm.id = ?
                ");
                $stmt->bind_param("i", $messageId);
                $stmt->execute();
                $result = $stmt->get_result();
                $newMessage = $result->fetch_assoc();
                $newMessage['message'] = customParse($newMessage['message'], $parsedown);
                $newMessage['timestamp'] = strtotime($newMessage['timestamp']);
                if ($newMessage['reply_to_id']) {
                    $replyStmt = $mysqli->prepare("
                        SELECT pm.message, u1.username as sender_username, u1.avatar as sender_avatar
                        FROM private_messages pm
                        JOIN users u1 ON pm.sender_id = u1.id
                        WHERE pm.id = ?
                    ");
                    $replyStmt->bind_param("i", $newMessage['reply_to_id']);
                    $replyStmt->execute();
                    $replyResult = $replyStmt->get_result();
                    if ($reply = $replyResult->fetch_assoc()) {
                        $newMessage['reply_to'] = [
                            'message' => customParse($reply['message'], $parsedown),
                            'username' => $reply['sender_username'],
                            'avatar' => $reply['sender_avatar']
                        ];
                    }
                    $replyStmt->close();
                } else {
                    $newMessage['reply_to'] = null;
                }
                echo json_encode(['success' => true, 'new_message' => $newMessage]);
            } else {
                error_log("Private message insert failed: " . $mysqli->error);
                echo json_encode(['success' => false, 'message' => '发送失败: ' . $mysqli->error]);
            }
            $stmt->close();
            $mysqli->close();
            break;

        case 'get_private_messages':
            // ... (Code with fix for recalled messages, unchanged)
            $receiver_id = intval($_POST['receiver_id'] ?? 0);
            if ($receiver_id <= 0) {
                echo json_encode(['success' => false, 'message' => '请选择接收者']);
                exit;
            }

            $mysqli = get_db_connection();
            $stmt = $mysqli->prepare("
                SELECT pm.*, u1.username as sender_username, u1.avatar as sender_avatar, u2.username as receiver_username
                FROM private_messages pm
                JOIN users u1 ON pm.sender_id = u1.id
                JOIN users u2 ON pm.receiver_id = u2.id
                WHERE ((pm.sender_id = ? AND pm.receiver_id = ?) OR (pm.sender_id = ? AND receiver_id = ?))
                AND pm.recalled = FALSE
                ORDER BY pm.timestamp DESC
            ");
            $stmt->bind_param("iiii", $_SESSION['user_id'], $receiver_id, $receiver_id, $_SESSION['user_id']);
            $stmt->execute();
            $result = $stmt->get_result();
            $messages = [];
            while ($row = $result->fetch_assoc()) {
                $row['message'] = customParse($row['message'], $parsedown);
                if ($row['reply_to_id']) {
                    $replyStmt = $mysqli->prepare("
                        SELECT pm.message, u1.username as sender_username, u1.avatar as sender_avatar
                        FROM private_messages pm
                        JOIN users u1 ON pm.sender_id = u1.id
                        WHERE pm.id = ?
                    ");
                    $replyStmt->bind_param("i", $row['reply_to_id']);
                    $replyStmt->execute();
                    $replyResult = $replyStmt->get_result();
                    if ($reply = $replyResult->fetch_assoc()) {
                        $row['reply_to'] = [
                            'message' => customParse($reply['message'], $parsedown),
                            'username' => $reply['sender_username'],
                            'avatar' => $reply['sender_avatar']
                        ];
                    }
                    $replyStmt->close();
                } else {
                    $row['reply_to'] = null;
                }
                $row['timestamp'] = strtotime($row['timestamp']);
                $messages[] = $row;
            }
            $stmt->close();
            $mysqli->close();
            echo json_encode(['success' => true, 'messages' => $messages]);
            break;

        case 'recall_message':
            // ... (Code for recalling a message, unchanged)
            $messageId = $_POST['message_id'] ?? '';
            $isPrivate = filter_var($_POST['is_private'] ?? 'false', FILTER_VALIDATE_BOOLEAN);

            if (empty($messageId)) {
                echo json_encode(['success' => false, 'message' => '消息 ID 无效']);
                exit;
            }

            if ($isPrivate) {
                $mysqli = get_db_connection();
                $stmt = $mysqli->prepare("SELECT id FROM private_messages WHERE id = ? AND sender_id = ? AND recalled = FALSE");
                $stmt->bind_param("ii", $messageId, $_SESSION['user_id']);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    $stmt->close();
                    $updateStmt = $mysqli->prepare("UPDATE private_messages SET recalled = TRUE WHERE id = ?");
                    $updateStmt->bind_param("i", $messageId);
                    if ($updateStmt->execute()) {
                        logAccess("Private message recalled by {$_SESSION['username']}, message_id: {$messageId}");
                        echo json_encode(['success' => true, 'message' => '私聊消息已撤回']);
                    } else {
                        echo json_encode(['success' => false, 'message' => '撤回失败: ' . $mysqli->error]);
                    }
                    $updateStmt->close();
                } else {
                    $stmt->close();
                    echo json_encode(['success' => false, 'message' => '消息未找到或无权撤回']);
                }
                $mysqli->close();
            } else {
                $messages = json_decode(file_get_contents($config['db_file']), true) ?: [];
                $found = false;
                foreach ($messages as $index => $msg) {
                    if ($msg['id'] === (string)$messageId && $msg['user_id'] === $_SESSION['user_id'] && !$msg['recalled']) {
                        $messages[$index]['recalled'] = true;
                        $found = true;
                        break;
                    }
                }
                if ($found) {
                    file_put_contents($config['db_file'], json_encode($messages, JSON_UNESCAPED_UNICODE), LOCK_EX);
                    logAccess("Public message recalled by {$_SESSION['username']}, message_id: {$messageId}");
                    echo json_encode(['success' => true, 'message' => '公共消息已撤回']);
                } else {
                    echo json_encode(['success' => false, 'message' => '消息未找到或无权撤回']);
                }
            }
            break;

        case 'check_new_messages':
            // ... (Code for polling new messages, unchanged)
            $lastPublicTimestamp = intval($_POST['lastPublicTimestamp'] ?? 0);
            $lastPrivateTimestamp = intval($_POST['lastPrivateTimestamp'] ?? 0);
            $currentReceiverId = intval($_POST['currentReceiverId'] ?? 0);

            $publicMessages = json_decode(file_get_contents($config['db_file']), true) ?: [];
            $newPublicMessages = array_filter($publicMessages, function($msg) use ($lastPublicTimestamp) {
                return $msg['timestamp'] > $lastPublicTimestamp && !($msg['recalled'] ?? false);
            });

            $parsedPublicMessages = [];
            foreach ($newPublicMessages as $msg) {
                $msg['message'] = customParse($msg['message'], $parsedown);
                if (!empty($msg['reply_to'])) {
                    $msg['reply_to']['message'] = customParse($msg['reply_to']['message'], $parsedown);
                }
                $parsedPublicMessages[] = $msg;
            }
            usort($parsedPublicMessages, fn($a, $b) => $a['timestamp'] - $b['timestamp']);

            $parsedPrivateMessages = [];
            if ($currentReceiverId > 0 && $_SESSION['user_id'] > 0) {
                $mysqli = get_db_connection();
                $stmt = $mysqli->prepare("
                    SELECT pm.*, u1.username as sender_username, u1.avatar as sender_avatar
                    FROM private_messages pm
                    JOIN users u1 ON pm.sender_id = u1.id
                    WHERE ((pm.sender_id = ? AND pm.receiver_id = ?) OR (pm.sender_id = ? AND pm.receiver_id = ?))
                    AND pm.timestamp > FROM_UNIXTIME(?) AND pm.recalled = FALSE
                    ORDER BY pm.timestamp ASC
                ");
                $stmt->bind_param("iiiii", $_SESSION['user_id'], $currentReceiverId, $currentReceiverId, $_SESSION['user_id'], $lastPrivateTimestamp);
                $stmt->execute();
                $result = $stmt->get_result();
                
                while ($row = $result->fetch_assoc()) {
                    $row['message'] = customParse($row['message'], $parsedown);
                    if ($row['reply_to_id']) {
                        $replyStmt = $mysqli->prepare("
                            SELECT pm.message, u1.username as sender_username
                            FROM private_messages pm
                            JOIN users u1 ON pm.sender_id = u1.id
                            WHERE pm.id = ?
                        ");
                        $replyStmt->bind_param("i", $row['reply_to_id']);
                        $replyStmt->execute();
                        if ($reply = $replyStmt->get_result()->fetch_assoc()) {
                            $row['reply_to'] = [
                                'message' => customParse($reply['message'], $parsedown),
                                'username' => $reply['sender_username']
                            ];
                        }
                        $replyStmt->close();
                    }
                    $row['timestamp'] = strtotime($row['timestamp']);
                    $parsedPrivateMessages[] = $row;
                }
                $stmt->close();
                $mysqli->close();
            }

            echo json_encode([
                'success' => true,
                'newPublicMessages' => $parsedPublicMessages,
                'newPrivateMessages' => $parsedPrivateMessages
            ]);
            break;
        case 'get_settings':
            $settings = getUserSettings($_SESSION['user_id']);
            echo json_encode(['success' => true, 'settings' => $settings]);
            break;
        case 'save_settings':
            $theme = intval($_POST['theme'] ?? 0);
            $radius = intval($_POST['radius'] ?? 20);
            $settings = ['theme' => $theme, 'radius' => $radius];
            saveUserSettings($_SESSION['user_id'], $settings);
            echo json_encode(['success' => true, 'message' => '设置保存成功']);
            break;
    }
    exit;
}

cleanOldRateFiles();
logAccess("Mobile page accessed by {$_SESSION['username']}");
$initialSettings = getUserSettings($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>VenlanChat</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/mathjax/3.2.2/es5/tex-mml-chtml.min.js" async></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/default.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"></script>
    <script>
        window.MathJax = {
            tex: {
                inlineMath: [['$', '$'], ['\\(', '\\)']],
                displayMath: [['$$', '$$'], ['\\[', '\\]']],
                processEscapes: true,
                processEnvironments: true
            },
            options: {
                skipHtmlTags: ['script', 'noscript', 'style', 'textarea', 'pre', 'code'],
                ignoreHtmlClass: 'tex2jax_ignore'
            }
        };
    </script>
    <style>
    /* 自定义滚动条样式 */
    ::-webkit-scrollbar {
        width: 8px; /* 设置滚动条的宽度 */
    }
    
    ::-webkit-scrollbar-track {
        background: var(--chat-bg); /* 滚动条轨道颜色随主题变化 */
        border: none; /* 移除白色边框 */
    }
    
    ::-webkit-scrollbar-thumb {
        background-color: var(--accent-color); /* 滚动条滑块颜色随主题变化 */
        border-radius: 4px; /* 设置滑块圆角 */
        border: none; /* 移除滑块上的任何边框 */
    }
    
    /* 针对输入框的滚动条样式 */
    textarea::-webkit-scrollbar {
        width: 8px; /* 滚动条宽度 */
        background-color: transparent; /* 背景透明 */
    }
    
    /* 隐藏滚动条上下的小尖头和任何可能的多余部分 */
    textarea::-webkit-scrollbar-button {
        height: 0;
        width: 0;
        display: none;
    }
    
    textarea::-webkit-scrollbar-track {
        background-color: transparent;
    }
    
    /* 确保轨道两端的可能多余部分也消失 */
    textarea::-webkit-scrollbar-track-piece:start {
        background: transparent;
        height: 0;
    }
    
    textarea::-webkit-scrollbar-track-piece:end {
        background: transparent;
        height: 0;
    }
    
    textarea::-webkit-scrollbar-thumb {
        background-color: var(--accent-color); /* 颜色随主题变化 */
        border-radius: 4px; /* 滑块圆角 */
        margin-right: 2px; /* 向左移动 */
        border: none;
    }
    
    /* 兼容 Firefox 浏览器 */
    textarea {
        scrollbar-width: thin;
        scrollbar-color: var(--accent-color) transparent;
    }
        :root {
            --bg-color: #eef1f5;
            --text-color: #1a202c;
            --chat-bg: #f7f9fc;
            --msg-bg: white;
            --own-msg-bg: #e3f6fe;
            --input-bg: #ffffff;
            --border-color: #e2e8f0;
            --accent-color: #4299e1;
            --secondary-text: #a0aec0;
            --username-color: #4a5568;
            --reply-bg: #f1f5f9;
            --reply-border: #3182ce;
            --own-reply-bg: #d4eaf5;
            --own-reply-border: #4299e1;
            --shadow-color: rgba(0,0,0,0.05);
            --danger-color: #e53e3e;
            --danger-color-hover: #c53030;
            --border-radius-msg: 20px;
            --border-radius-input: 24px;
            --border-radius-avatar: 50%;
            --border-radius-modal: 16px;
            --border-radius-btn: 50%;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        html, body {
            height: 100%;
            height: -webkit-fill-available;
            overflow: hidden;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            overscroll-behavior: none;
        }
        
        /* General Transition */
        body, input, textarea, button, .chat-container, .settings-container, .chat-sidebar, .message, .input-container {
            transition: background-color 0.3s, color 0.3s, border-color 0.3s;
        }

        #app {
            display: flex;
            flex-direction: column;
            height: 100vh;
            height: -webkit-fill-available;
            width: 100%;
            overflow-x: hidden;
        }

        .chat-sidebar {
            display: none;
        }

        .chat-container, .settings-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background: var(--chat-bg);
            position: relative;
            height: 100%;
            opacity: 1;
            transition: opacity 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .chat-container.fade-out, .settings-container.fade-out {
            opacity: 0;
            pointer-events: none;
        }

        .chat-container.fade-in, .settings-container.fade-in {
            animation: fadeIn 0.4s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 15px;
            -webkit-overflow-scrolling: touch;
            display: flex;
            flex-direction: column;
            gap: 14px;
            overscroll-behavior: contain;
        }

        .message {
            background: var(--msg-bg);
            padding: 16px 18px;
            border-radius: var(--border-radius-msg);
            box-shadow: 0 2px 10px var(--shadow-color);
            max-width: 85%;
            display: flex;
            flex-direction: column;
            align-self: flex-start;
            align-items: flex-start;
            animation: messageAppear 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }

        @keyframes messageAppear {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideInFromBottomToCenter {
            from {
                transform: translate(-50%, 100vh);
                opacity: 0;
            }
            to {
                transform: translate(-50%, -50%);
                opacity: 1;
            }
        }

        @keyframes slideOutFromCenterToBottom {
            from {
                transform: translate(-50%, -50%);
                opacity: 1;
            }
            to {
                transform: translate(-50%, 100vh);
                opacity: 0;
            }
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }

        @keyframes fadeOut {
            from {
                opacity: 1;
            }
            to {
                opacity: 0;
            }
        }

        @keyframes scaleIn {
            from {
                opacity: 0;
                transform: scale(0.9);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        @keyframes scaleOut {
            from {
                opacity: 1;
                transform: scale(1);
            }
            to {
                opacity: 0;
                transform: scale(0.9);
            }
        }

        @keyframes slideInFromBottom {
            from {
                opacity: 0;
                transform: translateY(100%);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideOutToBottom {
            from {
                opacity: 1;
                transform: translateY(0);
            }
            to {
                opacity: 0;
                transform: translateY(100%);
            }
        }

        .message.own {
            background: var(--own-msg-bg);
            align-self: flex-end;
        }

        .message-header {
            display: flex;
            align-items: center;
            margin-bottom: 6px;
            width: 100%;
        }

        .message.own .message-header {
            flex-direction: row-reverse;
        }

        .avatar {
            width: 40px;
            height: 40px;
            border-radius: var(--border-radius-avatar);
            object-fit: cover;
            margin-right: 12px;
            border: 2px solid #fff;
            box-shadow: 0 2px 6px var(--shadow-color);
        }

        .message.own .avatar {
            margin-left: 12px;
            margin-right: 0;
        }

        .username {
            font-weight: 600;
            color: var(--username-color);
            font-size: 1rem;
        }

        .timestamp {
            font-size: 0.8rem;
            color: var(--secondary-text);
            margin-left: auto;
            white-space: nowrap;
        }

        .message-content {
            line-height: 1.6;
            color: var(--text-color);
            overflow-wrap: break-word;
            width: 100%;
            font-size: 1rem;
        }

        .message-content img {
            max-width: 100%;
            border-radius: 8px;
            margin-top: 8px;
        }

        .reply-preview {
            background: var(--reply-bg);
            border-left: 3px solid var(--reply-border);
            padding: 10px 12px;
            border-radius: 10px;
            margin-bottom: 10px;
            font-size: 0.9rem;
            color: var(--secondary-text);
            width: 100%;
            display: flex;
            justify-content: space-between;
            align-items: center;
            min-height: 44px;
        }

        .message.own .reply-preview {
            background: var(--own-reply-bg);
            border-left: 3px solid var(--own-reply-border);
        }

        .reply-cancel-btn {
            background: transparent;
            border: none;
            color: var(--secondary-text);
            cursor: pointer;
            font-size: 1.2rem;
            padding: 8px;
            transition: all 0.2s;
            min-width: 40px;
            min-height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .reply-cancel-btn:active {
            background: var(--chat-bg);
            transform: scale(0.9);
        }

        .input-container {
            background: var(--input-bg);
            padding: 12px;
            border-top: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: stretch;
            gap: 10px;
            flex-shrink: 0;
            z-index: 99;
        }

        .input-row {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .message-input {
            flex: 1;
            border: 2px solid var(--border-color);
            background-color: var(--msg-bg);
            color: var(--text-color);
            border-radius: var(--border-radius-input);
            padding: 14px 22px;
            font-size: 1.05rem;
            resize: none;
            max-height: 120px;
            outline: none;
            transition: all 0.2s ease-in-out;
            border-top-right-radius: 3px;
            border-bottom-right-radius: 3px;
            line-height: 1.5;
            -webkit-appearance: none;
        }

        .message-input:focus {
            border-color: var(--accent-color);
            box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-color) 20%, transparent);
        }

        .send-btn {
            background: var(--accent-color);
            color: white;
            border: none;
            min-width: 52px;
            min-height: 52px;
            width: 52px;
            height: 52px;
            border-radius: var(--border-radius-btn);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 4px 12px color-mix(in srgb, var(--accent-color) 35%, transparent);
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            flex-shrink: 0;
        }

        .send-btn:active {
            transform: scale(0.92);
            box-shadow: 0 2px 6px color-mix(in srgb, var(--accent-color) 35%, transparent);
        }
        
        .input-focus-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.08);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            z-index: 101;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease-out;
        }

        .input-focus-overlay.active {
            opacity: 1;
            pointer-events: all;
        }

        .input-container.focused {
            position: fixed;
            bottom: auto;
            top: 50%;
            left: 50%;
            width: 90vw;
            max-width: 500px;
            border-radius: var(--border-radius-modal);
            background: var(--input-bg);
            box-shadow: 0 6px 24px 0 var(--shadow-color);
            border: 1px solid var(--border-color);
            z-index: 102;
            transform: translate(-50%, -50%);
            animation: slideInFromBottomToCenter 0.25s cubic-bezier(0.34, 1.3, 0.64, 1);
        }
        
        .input-container.unfocusing {
            animation: slideOutFromCenterToBottom 0.22s cubic-bezier(0.4, 0, 0.68, 0.06) forwards;
        }

        .bottom-nav {
            display: flex;
            background: var(--input-bg);
            border-top: 1px solid var(--border-color);
            padding: 10px 0;
            flex-shrink: 0;
            box-shadow: 0 -2px 10px var(--shadow-color);
            position: relative;
            z-index: 100;
        }

        .nav-item {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 10px 8px;
            color: var(--secondary-text);
            font-size: 0.8rem;
            font-weight: 600;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
            min-height: 58px;
            -webkit-tap-highlight-color: transparent;
        }

        .nav-item:active {
            transform: scale(0.95);
            background: var(--chat-bg);
            border-radius: 12px;
        }

        .nav-item.active {
            color: var(--accent-color);
        }

        .nav-item.active::before {
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 40px;
            height: 3px;
            background: var(--accent-color);
            border-radius: 0 0 3px 3px;
        }

        .nav-icon {
            font-size: 1.5rem;
            margin-bottom: 5px;
        }

        .modal, .chat-selector-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1),
                        background-color 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .modal.active, .chat-selector-modal.active {
            opacity: 1;
            pointer-events: all;
            background: rgba(0,0,0,0.6);
        }

        .modal.closing, .chat-selector-modal.closing {
            animation: fadeOut 0.3s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .modal-content, .chat-selector-content {
            background: var(--input-bg);
            width: 90%;
            max-width: 450px;
            border-radius: var(--border-radius-modal);
            padding: 24px;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 8px 32px var(--shadow-color);
            transform: scale(0.9) translateY(20px);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        .modal.active .modal-content,
        .chat-selector-modal.active .chat-selector-content {
            transform: scale(1) translateY(0);
            opacity: 1;
        }

        .modal.closing .modal-content,
        .chat-selector-modal.closing .chat-selector-content {
            animation: scaleOut 0.25s cubic-bezier(0.4, 0, 1, 1) forwards;
        }

        .chat-selector-content {
            background: var(--chat-bg);
        }

        .user-list-container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(90px, 1fr));
            gap: 16px;
            padding: 10px 0;
            width: 100%;
        }

        .user-item.grid-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            padding: 14px 10px;
            border-radius: 14px;
            background: var(--msg-bg);
            box-shadow: 0 2px 8px var(--shadow-color);
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            -webkit-tap-highlight-color: transparent;
            min-height: 120px;
        }

        .user-item.grid-item:active {
            background-color: var(--chat-bg);
            transform: scale(0.96);
            box-shadow: 0 1px 4px var(--shadow-color);
        }

        .user-item.grid-item .avatar {
            width: 68px;
            height: 68px;
            margin: 0 auto 12px;
        }

        .user-item.grid-item .user-name {
            font-weight: 600;
            color: var(--text-color);
            font-size: 0.95rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            width: 100%;
        }

        #scrollToBottomBtn {
            position: absolute;
            bottom: 20px;
            right: 20px;
            left: auto;
            width: 56px;
            height: 56px;
            background-color: var(--accent-color);
            color: white;
            border: none;
            border-radius: var(--border-radius-btn);
            display: flex;
            justify-content: center;
            align-items: center;
            cursor: pointer;
            box-shadow: 0 6px 16px color-mix(in srgb, var(--accent-color) 40%, transparent);
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            z-index: 10;
            font-size: 1.2rem;
        }

        #scrollToBottomBtn.visible {
            opacity: 1;
            visibility: visible;
        }

        #scrollToBottomBtn:active {
            transform: scale(0.9);
        }

        .context-menu {
            position: fixed;
            background: var(--msg-bg);
            border-radius: 14px;
            box-shadow: 0 8px 24px var(--shadow-color);
            z-index: 1001;
            overflow: hidden;
            min-width: 140px;
        }

        .context-item {
            padding: 16px 28px;
            border-bottom: 1px solid var(--chat-bg);
            cursor: pointer;
            font-size: 1rem;
            color: var(--text-color);
            transition: all 0.2s;
            -webkit-tap-highlight-color: transparent;
            min-height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 500;
        }

        .context-item:active {
            background-color: var(--chat-bg);
            transform: scale(0.97);
        }

        .context-item:last-child {
            border-bottom: none;
        }
        
        /* --- Improved Settings Page Styles --- */
        .settings-section {
            padding: 25px;
            overflow-y: auto;
            flex: 1;
            background-color: var(--bg-color);
        }

        .settings-section h2 {
            color: var(--text-color);
            margin-bottom: 30px;
            font-size: 1.75rem;
            padding-bottom: 15px;
            font-weight: 800;
            text-align: center;
            position: relative;
        }

        .settings-section h2::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 4px;
            background: var(--accent-color);
            border-radius: 2px;
        }

        .settings-group {
            background-color: var(--chat-bg);
            padding: 30px;
            border-radius: var(--border-radius-modal);
            margin-bottom: 30px;
            box-shadow: 0 6px 16px var(--shadow-color);
            border: 1px solid var(--border-color);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            animation: slideUp 0.5s cubic-bezier(0.4, 0, 0.2, 1);
            opacity: 0;
            animation: slideUp 0.5s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .settings-group:nth-child(1) {
            animation-delay: 0s;
        }

        .settings-group:nth-child(2) {
            animation-delay: 0.1s;
        }

        .settings-group:nth-child(3) {
            animation-delay: 0.2s;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .settings-group:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 24px var(--shadow-color);
        }

        .settings-group h3 {
            color: var(--text-color);
            margin-bottom: 25px;
            font-size: 1.3rem;
            font-weight: 700;
            position: relative;
            padding-bottom: 15px;
        }

        .settings-group h3::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 40px;
            height: 3px;
            background: var(--accent-color);
            border-radius: 1.5px;
        }

        .setting-item {
            margin-bottom: 30px;
            padding: 20px;
            background: var(--msg-bg);
            border-radius: 16px;
            box-shadow: 0 4px 8px var(--shadow-color);
            border: 1px solid var(--border-color);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            animation: fadeInScale 0.5s ease-out;
        }

        @keyframes fadeInScale {
            from {
                opacity: 0;
                transform: scale(0.95);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        .setting-item:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 16px var(--shadow-color);
        }

        .setting-item label {
            display: block;
            margin-bottom: 15px;
            font-weight: 700;
            color: var(--username-color);
            font-size: 1.2rem;
            text-align: center;
        }
        
        .profile-header {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 25px 0 30px;
            margin-bottom: 25px;
            border-bottom: 2px dashed var(--border-color);
        }

        .profile-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            object-fit: cover;
            margin-bottom: 20px;
            border: 5px solid var(--accent-color);
            box-shadow: 0 8px 20px var(--shadow-color);
            transition: transform 0.3s ease;
        }

        .profile-avatar:hover {
            transform: scale(1.05);
        }

        .profile-username {
            font-size: 1.8rem;
            font-weight: 800;
            color: var(--text-color);
            margin-bottom: 5px;
            text-shadow: 0 2px 4px var(--shadow-color);
        }

        .form-group {
            margin-bottom: 25px;
        }

        .form-group label {
            display: block;
            margin-bottom: 10px;
            font-weight: 600;
            color: var(--username-color);
            font-size: 1.1rem;
        }

        .form-group input[type="text"] {
            width: 100%;
            padding: 14px 18px;
            border: 2px solid var(--border-color);
            border-radius: 12px;
            font-size: 1.1rem;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 6px var(--shadow-color);
        }

        .form-group input[type="text"]:focus {
            outline: none;
            border-color: var(--accent-color);
            box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent-color) 20%, transparent);
            transform: translateY(-2px);
        }

        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
            width: 100%;
        }

        .file-input-btn {
            background: var(--secondary-text);
            color: var(--bg-color);
            border: none;
            padding: 12px 20px;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 6px var(--shadow-color);
            width: 100%;
            text-align: center;
        }

        .file-input-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 12px var(--shadow-color);
            filter: brightness(1.1);
        }

        .file-input-btn:active {
            transform: translateY(1px);
            box-shadow: 0 2px 4px var(--shadow-color);
        }

        .file-input-wrapper input[type="file"] {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }

        .file-name {
            margin-top: 12px;
            color: var(--secondary-text);
            font-size: 1rem;
            font-weight: 500;
            text-align: center;
            padding: 8px 12px;
            background: var(--msg-bg);
            border-radius: 8px;
            box-shadow: 0 2px 4px var(--shadow-color);
        }
        
        .theme-selector {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
            gap: 20px;
            margin-top: 15px;
            padding: 10px 0;
        }

        .theme-option {
            border: 2px solid var(--border-color);
            border-radius: 18px;
            padding: 22px 12px;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            background: var(--msg-bg);
            box-shadow: 0 2px 8px var(--shadow-color);
            -webkit-tap-highlight-color: transparent;
            min-height: 110px;
        }

        .theme-option:active {
            transform: scale(0.95);
            box-shadow: 0 1px 4px var(--shadow-color);
        }

        .theme-option.active {
            border-color: var(--accent-color);
            border-width: 3px;
            transform: scale(1.02);
            box-shadow: 0 6px 16px color-mix(in srgb, var(--accent-color) 25%, transparent);
        }

        .theme-color {
            width: 46px;
            height: 46px;
            border-radius: 50%;
            margin: 0 auto 14px;
            border: 3px solid var(--border-color);
            box-shadow: 0 2px 6px var(--shadow-color);
        }

        .theme-name {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-color);
            line-height: 1.4;
        }

        .slider-container {
            width: 100%;
            padding: 20px 0;
        }

        .slider {
            -webkit-appearance: none;
            width: 100%;
            height: 12px;
            border-radius: 6px;
            background: linear-gradient(to right, var(--accent-color), var(--accent-color)) no-repeat, var(--bg-color);
            background-size: 0% 100%, 100% 100%;
            outline: none;
            transition: background 0.3s;
            cursor: pointer;
        }

        .slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: var(--accent-color);
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px var(--shadow-color);
            border: 3px solid white;
        }

        .slider:active::-webkit-slider-thumb {
            transform: scale(1.15);
            box-shadow: 0 4px 12px var(--shadow-color);
        }
        
        .slider-value {
            text-align: center;
            margin-top: 12px;
            color: var(--text-color);
            font-size: 1rem;
            font-weight: 600;
            background: var(--msg-bg);
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            box-shadow: 0 2px 6px var(--shadow-color);
        }

        .settings-actions {
            display: flex;
            gap: 20px;
            margin-top: 30px;
        }
        
        .action-btn {
            flex: 1;
            color: white;
            border: none;
            padding: 18px;
            border-radius: 14px;
            cursor: pointer;
            font-size: 1.05rem;
            font-weight: 700;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 10px var(--shadow-color);
            min-height: 54px;
            -webkit-tap-highlight-color: transparent;
        }

        .action-btn:active {
            transform: scale(0.96);
            box-shadow: 0 2px 6px var(--shadow-color);
        }

        .save-btn {
            background: var(--accent-color);
        }

        .cancel-btn {
            background: var(--secondary-text);
        }

        #logoutBtn {
            width: 100%;
            background: var(--danger-color);
            padding: 20px;
            font-size: 1.05rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            min-height: 58px;
            border-radius: 14px;
            -webkit-tap-highlight-color: transparent;
        }

        #logoutBtn:active {
            transform: scale(0.96);
        }

        /* --- NEW: Toast & Confirm Modal Styles --- */
        .toast-notification {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%) translateY(-150%);
            padding: 14px 28px;
            border-radius: 12px;
            color: white;
            font-weight: 600;
            z-index: 9999;
            opacity: 0;
            transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
            pointer-events: none;
            font-size: 1rem;
            letter-spacing: 0.3px;
        }

        .toast-notification.show {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
            pointer-events: auto;
        }

        .toast-notification.hide {
            animation: slideOutToTop 0.3s cubic-bezier(0.4, 0, 1, 1) forwards;
        }

        @keyframes slideOutToTop {
            to {
                opacity: 0;
                transform: translateX(-50%) translateY(-150%);
            }
        }

        .toast-notification.success {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
        }
        .toast-notification.error {
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }

        .loader {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            font-size: 1rem;
            color: var(--secondary-text);
            margin: 40px 0;
            animation: fadeIn 0.5s ease-in-out;
        }

        .loader i {
            animation: spin 2s linear infinite;
            font-size: 1.8rem;
            color: var(--accent-color);
        }

        #confirmModal .modal-content {
            padding: 30px;
            text-align: center;
        }
        #confirmModalText {
            font-size: 1.1rem;
            color: var(--text-color);
            margin-bottom: 25px;
            line-height: 1.6;
            animation: slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1) 0.1s both;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .confirm-modal-actions {
            display: flex;
            justify-content: center;
            gap: 15px;
            animation: slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1) 0.2s both;
        }
        .confirm-modal-actions button {
            flex: 1;
            padding: 16px 24px;
            border-radius: 12px;
            font-size: 1.05rem;
            font-weight: 700;
            border: none;
            cursor: pointer;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            min-height: 52px;
            -webkit-tap-highlight-color: transparent;
        }
         .confirm-modal-actions button:active {
            transform: scale(0.95);
         }
        #confirmModalYes {
            background-color: var(--danger-color);
            color: white;
        }
         #confirmModalYes:hover {
            background-color: var(--danger-color-hover);
         }
        #confirmModalNo {
            background-color: var(--border-color);
            color: var(--text-color);
        }
         #confirmModalNo:hover {
            filter: brightness(0.95);
         }


        @media (min-width: 768px) {
            #app {
                flex-direction: row;
                justify-content: center;
                align-items: stretch;
                padding: 0;
                background: var(--bg-color);
                color: var(--text-color);
                width: 100vw;
                height: 100vh;
                max-width: none;
                margin: 0;
                border-radius: 0;
                box-shadow: none;
                overflow: hidden;
                height: -webkit-fill-available;
                border: none;
            }

            .chat-sidebar {
                display: flex;
                flex-direction: column;
                width: 280px;
                height: 100%;
                background: var(--input-bg);
                border-right: 1px solid var(--border-color);
                box-shadow: 0 4px 20px var(--shadow-color);
                border-radius: 0;
                margin-right: 0;
            }
            
            .chat-container, .settings-container {
                flex: 1;
                height: 100%;
                border-radius: 0;
                box-shadow: none;
                border-top: none;
                max-width: 100%;
            }
            
            #messagesContainer { padding: 20px; }
            .message { max-width: 600px; }
            
            .chat-sidebar-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px;
                border-bottom: 1px solid var(--border-color);
            }
            
            .chat-sidebar-header h2 { font-size: 1.1rem; color: var(--text-color); }
            
            .profile-btn {
                background: var(--bg-color);
                border-radius: var(--border-radius-btn);
                width: 40px;
                height: 40px;
                display: flex;
                justify-content: center;
                align-items: center;
                cursor: pointer;
                transition: background-color 0.2s;
            }
            
            .profile-btn:hover { background: var(--border-color); }
            
            .user-list-container {
                display: flex;
                flex-direction: column;
                gap: 4px;
                padding: 10px;
                overflow-y: auto;
                flex: 1;
            }

            .user-item {
                display: flex;
                align-items: center;
                padding: 10px 12px;
                border-radius: 12px;
                cursor: pointer;
                transition: background-color 0.2s;
            }

            .user-item:hover, .user-item.active { background-color: var(--bg-color); }

            .user-item .avatar {
                width: 48px;
                height: 48px;
                margin-right: 12px;
                border: 2px solid var(--input-bg);
            }
            
            .user-item.public .avatar { display: none; }
            .user-item .user-name {
                font-size: 1rem;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }

            .bottom-nav, .chat-selector-modal { display: none; }
            .input-container { position: relative; }
            
            #scrollToBottomBtn {
                right: 20px;
                left: auto;
                bottom: 20px;
            }

            .message-input { max-height: 200px; }
            .loader { margin: auto; }

            .input-container.focused {
                position: relative;
                top: auto;
                left: auto;
                transform: none;
                width: auto;
                background: var(--input-bg);
                box-shadow: none;
                border-radius: 0;
                animation: none;
            }
            .input-focus-overlay.active { display: none; }
        }

        /* --- Code Block Styles --- */
        pre code.hljs {
            border-radius: 8px;
            padding: 16px;
            background: var(--msg-bg);
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 6px var(--shadow-color);
            overflow-x: auto;
            font-size: 0.9rem;
            line-height: 1.4;
            color: var(--text-color);
        }

        pre[class*="language-"] {
            border-radius: 8px;
            margin: 12px 0;
            background: var(--msg-bg);
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 6px var(--shadow-color);
        }

        code.hljs {
            background: var(--msg-bg);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid var(--border-color);
            color: var(--text-color);
        }

        /* Theme-specific code highlighting adjustments */
        /* All themes use light color for code highlighting */
        [data-theme="0"] pre code.hljs,
        [data-theme="0"] code.hljs,
        [data-theme="1"] pre code.hljs,
        [data-theme="1"] code.hljs,
        [data-theme="2"] pre code.hljs,
        [data-theme="2"] code.hljs,
        [data-theme="3"] pre code.hljs,
        [data-theme="3"] code.hljs,
        [data-theme="4"] pre code.hljs,
        [data-theme="4"] code.hljs,
        [data-theme="5"] pre code.hljs,
        [data-theme="5"] code.hljs,
        [data-theme="6"] pre code.hljs,
        [data-theme="6"] code.hljs,
        [data-theme="7"] pre code.hljs,
        [data-theme="7"] code.hljs,
        [data-theme="8"] pre code.hljs,
        [data-theme="8"] code.hljs,
        [data-theme="9"] pre code.hljs,
        [data-theme="9"] code.hljs {
            color: #0f172a;
            background: #ffffff;
        }

        @media (min-width: 1200px) {
            #scrollToBottomBtn { right: 20px; left: auto; }
        }
    </style>
</head>
<body>
    <div id="app">
            <div id="inputFocusOverlay" class="input-focus-overlay"></div>

            <div class="chat-sidebar">
            <div class="chat-sidebar-header">
                <h2>VenlanChat</h2>
                <div class="profile-btn" id="profileBtnDesktop">
                    <i class="fas fa-user-circle"></i>
                </div>
            </div>
            <div class="user-list-container" id="desktopUserList">
                <div class="user-item active public" data-chat-type="public" data-chat-name="公共聊天">
                    <div class="user-name">公共聊天</div>
                </div>
                <?php foreach (getUserList() as $user): ?>
                <div class="user-item" data-chat-type="private" data-user-id="<?php echo $user['id']; ?>" data-user-name="<?php echo htmlspecialchars($user['username']); ?>">
                    <img src="<?php echo $user['avatar']; ?>" class="avatar" alt="<?php echo htmlspecialchars($user['username']); ?>">
                    <div class="user-name"><?php echo htmlspecialchars($user['username']); ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="chat-container" id="chatContainer">
            <div class="messages-container" id="messagesContainer">
                <div class="loader" id="loader"><i class="fas fa-spinner fa-spin"></i> 加载中...</div>
            </div>

            <div class="input-container">
                <div class="reply-preview" id="replyPreview" style="display: none;">
                    <span class="reply-preview-content"></span>
                    <button class="reply-cancel-btn" id="replyCancelBtn"><i class="fas fa-times"></i></button>
                </div>
                <div class="input-row">
                    <textarea class="message-input" id="messageInput" placeholder="输入消息..." rows="1"></textarea>
                    <button class="send-btn" id="sendBtn"><i class="fas fa-paper-plane"></i></button>
                </div>
            </div>
        </div>

        <div class="settings-container" id="settingsContainer" style="display: none;">
            <div class="settings-section">
                <h2>用户设置</h2>
                
                <div class="settings-group">
                    <div class="profile-header">
                        <img id="profileAvatar" src="<?php echo $current_user['avatar']; ?>" class="profile-avatar" alt="Avatar">
                        <div class="profile-username" id="profileUsername"><?php echo htmlspecialchars($current_user['username']); ?></div>
                    </div>
                    
                    <form id="profileForm">
                         <h3>个人资料</h3>
                        <div class="form-group">
                            <label for="usernameInput">用户名</label>
                            <input type="text" id="usernameInput" name="username" value="<?php echo htmlspecialchars($current_user['username']); ?>" required>
                        </div>
                        <div class="form-group">
                            <label>头像</label>
                            <div class="file-input-wrapper">
                                <button type="button" class="file-input-btn">选择图片</button>
                                <input type="file" id="avatarInput" name="avatar" accept="image/*">
                            </div>
                            <span class="file-name" id="fileName">未选择文件</span>
                        </div>
                        <div class="settings-actions">
                             <button type="submit" class="action-btn save-btn">保存个人信息</button>
                        </div>
                    </form>
                </div>

                <div class="settings-group">
                    <h3>外观设置</h3>
                    <div class="setting-item">
                        <label>页面圆角 (px)</label>
                        <div class="slider-container">
                            <input type="range" min="0" max="50" class="slider" id="radiusSlider">
                            <div class="slider-value" id="radiusValue">20 px</div>
                        </div>
                    </div>
                    <div class="setting-item">
                        <label>色彩风格</label>
                        <div class="theme-selector">
                            <div class="theme-option" data-theme="0">
                                <div class="theme-color" style="background: #3b82f6;"></div>
                                <div class="theme-name">默认白天</div>
                            </div>
                            <div class="theme-option" data-theme="1">
                                <div class="theme-color" style="background: #60a5fa;"></div>
                                <div class="theme-name">默认夜晚</div>
                            </div>
                            <div class="theme-option" data-theme="2">
                                <div class="theme-color" style="background: #0ea5e9;"></div>
                                <div class="theme-name">蓝色白天</div>
                            </div>
                            <div class="theme-option" data-theme="3">
                                <div class="theme-color" style="background: #38bdf8;"></div>
                                <div class="theme-name">蓝色夜晚</div>
                            </div>
                            <div class="theme-option" data-theme="4">
                                <div class="theme-color" style="background: #22c55e;"></div>
                                <div class="theme-name">绿色白天</div>
                            </div>
                            <div class="theme-option" data-theme="5">
                                <div class="theme-color" style="background: #4ade80;"></div>
                                <div class="theme-name">绿色夜晚</div>
                            </div>
                            <div class="theme-option" data-theme="6">
                                <div class="theme-color" style="background: #8b5cf6;"></div>
                                <div class="theme-name">紫色白天</div>
                            </div>
                            <div class="theme-option" data-theme="7">
                                <div class="theme-color" style="background: #a78bfa;"></div>
                                <div class="theme-name">紫色夜晚</div>
                            </div>
                            <div class="theme-option" data-theme="8">
                                <div class="theme-color" style="background: #f97316;"></div>
                                <div class="theme-name">橙色白天</div>
                            </div>
                            <div class="theme-option" data-theme="9">
                                <div class="theme-color" style="background: #fb923c;"></div>
                                <div class="theme-name">橙色夜晚</div>
                            </div>
                        </div>
                    </div>
                    <div class="settings-actions">
                        <button class="action-btn save-btn" id="saveSettingsBtn">保存设置</button>
                        <button class="action-btn cancel-btn" id="cancelSettingsBtn">撤销更改</button>
                    </div>
                </div>

                <div class="settings-group">
                     <h3>账户操作</h3>
                     <button class="action-btn" id="logoutBtn">退出登录</button>
                </div>
            </div>
        </div>

        <div class="bottom-nav">
            <div class="nav-item active" id="publicChatBtn">
                <div class="nav-icon"><i class="fas fa-comments"></i></div>
                <div>公共聊天</div>
            </div>
            <div class="nav-item" id="privateChatBtn">
                <div class="nav-icon"><i class="fas fa-user-friends"></i></div>
                <div>私聊</div>
            </div>
            <div class="nav-item" id="settingsBtn">
                <div class="nav-icon"><i class="fas fa-cog"></i></div>
                <div>用户</div>
            </div>
        </div>
    </div>
    <button id="scrollToBottomBtn"><i class="fas fa-arrow-down"></i></button>
</div>

    <div class="chat-selector-modal" id="chatSelectorModal">
        <div class="chat-selector-content">
            <h2 style="margin-bottom: 10px;">请选择聊天对象</h2>
            <div class="user-list-container">
                <?php foreach (getUserList() as $user): ?>
                <div class="user-item grid-item" data-user-id="<?php echo $user['id']; ?>">
                    <img src="<?php echo $user['avatar']; ?>" class="avatar" alt="<?php echo htmlspecialchars($user['username']); ?>">
                    <div class="user-name"><?php echo htmlspecialchars($user['username']); ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
    
    <div class="modal" id="confirmModal">
        <div class="modal-content" id="confirmModalContent">
            <p id="confirmModalText"></p>
            <div class="confirm-modal-actions">
                <button id="confirmModalYes">确认</button>
                <button id="confirmModalNo">取消</button>
            </div>
        </div>
    </div>


    <script>
        // --- State Variables ---
        let latestPublicTimestamp = 0;
        let latestPrivateTimestamp = 0;
        let pollingInterval = null;
        let isPublicChat = true;
        let selectedReceiverId = null;
        let replyToId = null;
        let currentTab = 'public';
        
        // --- Settings State ---
        let savedSettings = <?php echo json_encode($initialSettings); ?>;
        let currentSettings = JSON.parse(JSON.stringify(savedSettings));

        // --- DOM Elements ---
        const messagesContainer = document.getElementById('messagesContainer');
        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        const publicChatBtn = document.getElementById('publicChatBtn');
        const privateChatBtn = document.getElementById('privateChatBtn');
        const settingsBtn = document.getElementById('settingsBtn');
        const chatSelectorModal = document.getElementById('chatSelectorModal');
        const logoutBtn = document.getElementById('logoutBtn');
        const scrollToBottomBtn = document.getElementById('scrollToBottomBtn');
        const profileForm = document.getElementById('profileForm');
        const avatarInput = document.getElementById('avatarInput');
        const profileAvatar = document.getElementById('profileAvatar');
        const replyPreview = document.getElementById('replyPreview');
        const replyPreviewContent = replyPreview.querySelector('.reply-preview-content');
        const replyCancelBtn = document.getElementById('replyCancelBtn');
        const inputContainer = document.querySelector('.input-container');
        const bottomNav = document.querySelector('.bottom-nav');
        const desktopUserList = document.getElementById('desktopUserList');
        const inputFocusOverlay = document.getElementById('inputFocusOverlay');
        const chatContainer = document.getElementById('chatContainer');
        const settingsContainer = document.getElementById('settingsContainer');

        const isDesktop = window.matchMedia("(min-width: 768px)").matches;
        const currentUserId = <?php echo $_SESSION['user_id']; ?>;

        const themes = [
            // 默认白天 - 清新蓝调
            {
                bg: '#f8fafc', text: '#1e293b', chatBg: '#f1f5f9', msgBg: '#ffffff', ownMsgBg: '#e0f2fe',
                inputBg: '#ffffff', border: '#e2e8f0', accent: '#0284c7', secondary: '#94a3b8', username: '#334155',
                replyBg: '#f0f9ff', replyBorder: '#0ea5e9', ownReplyBg: '#dbeafe', ownReplyBorder: '#0284c7',
                shadow: 'rgba(0,0,0,0.04)', danger: '#ef4444', dangerHover: '#dc2626'
            },
            // 默认夜晚 - 深邃星空
            {
                bg: '#0f172a', text: '#e2e8f0', chatBg: '#1e293b', msgBg: '#293548', ownMsgBg: '#1e3a5f',
                inputBg: '#1e293b', border: '#334155', accent: '#38bdf8', secondary: '#94a3b8', username: '#cbd5e1',
                replyBg: '#1e3148', replyBorder: '#0ea5e9', ownReplyBg: '#1e3a5f', ownReplyBorder: '#38bdf8',
                shadow: 'rgba(0,0,0,0.4)', danger: '#f87171', dangerHover: '#ef4444'
            },
            // 蓝色白天 - 海洋微风
            {
                bg: '#f0f9ff', text: '#0c4a6e', chatBg: '#e0f2fe', msgBg: '#ffffff', ownMsgBg: '#bfdbfe',
                inputBg: '#ffffff', border: '#bae6fd', accent: '#0284c7', secondary: '#0ea5e9', username: '#075985',
                replyBg: '#dbeafe', replyBorder: '#0284c7', ownReplyBg: '#bfdbfe', ownReplyBorder: '#0ea5e9',
                shadow: 'rgba(14,165,233,0.08)', danger: '#ef4444', dangerHover: '#dc2626'
            },
            // 蓝色夜晚 - 深海静谧
            {
                bg: '#0c1e35', text: '#e0f2fe', chatBg: '#0f2942', msgBg: '#1e3a5f', ownMsgBg: '#1e4776',
                inputBg: '#0f2942', border: '#1e3a5f', accent: '#38bdf8', secondary: '#7dd3fc', username: '#bae6fd',
                replyBg: '#1e3a5f', replyBorder: '#38bdf8', ownReplyBg: '#1e4776', ownReplyBorder: '#60a5fa',
                shadow: 'rgba(0,0,0,0.5)', danger: '#f87171', dangerHover: '#ef4444'
            },
            // 绿色白天 - 清新自然
            {
                bg: '#f0fdf4', text: '#14532d', chatBg: '#dcfce7', msgBg: '#ffffff', ownMsgBg: '#bbf7d0',
                inputBg: '#ffffff', border: '#bbf7d0', accent: '#16a34a', secondary: '#22c55e', username: '#166534',
                replyBg: '#d1fae5', replyBorder: '#10b981', ownReplyBg: '#bbf7d0', ownReplyBorder: '#16a34a',
                shadow: 'rgba(34,197,94,0.08)', danger: '#ef4444', dangerHover: '#dc2626'
            },
            // 绿色夜晚 - 森林暮色
            {
                bg: '#0a2818', text: '#d1fae5', chatBg: '#0f3a25', msgBg: '#16543a', ownMsgBg: '#166534',
                inputBg: '#0f3a25', border: '#16543a', accent: '#34d399', secondary: '#6ee7b7', username: '#a7f3d0',
                replyBg: '#16543a', replyBorder: '#10b981', ownReplyBg: '#166534', ownReplyBorder: '#34d399',
                shadow: 'rgba(0,0,0,0.5)', danger: '#f87171', dangerHover: '#ef4444'
            },
            // 紫色白天 - 薰衣草梦境
            {
                bg: '#faf5ff', text: '#581c87', chatBg: '#f3e8ff', msgBg: '#ffffff', ownMsgBg: '#e9d5ff',
                inputBg: '#ffffff', border: '#e9d5ff', accent: '#9333ea', secondary: '#a855f7', username: '#6b21a8',
                replyBg: '#f3e8ff', replyBorder: '#9333ea', ownReplyBg: '#e9d5ff', ownReplyBorder: '#a855f7',
                shadow: 'rgba(147,51,234,0.08)', danger: '#ef4444', dangerHover: '#dc2626'
            },
            // 紫色夜晚 - 神秘星云
            {
                bg: '#2e1065', text: '#f3e8ff', chatBg: '#4c1d95', msgBg: '#5b21b6', ownMsgBg: '#6d28d9',
                inputBg: '#4c1d95', border: '#5b21b6', accent: '#c084fc', secondary: '#d8b4fe', username: '#e9d5ff',
                replyBg: '#5b21b6', replyBorder: '#a855f7', ownReplyBg: '#6d28d9', ownReplyBorder: '#c084fc',
                shadow: 'rgba(0,0,0,0.5)', danger: '#f87171', dangerHover: '#ef4444'
            },
            // 橙色白天 - 暖阳午后
            {
                bg: '#fff7ed', text: '#7c2d12', chatBg: '#ffedd5', msgBg: '#ffffff', ownMsgBg: '#fed7aa',
                inputBg: '#ffffff', border: '#fdba74', accent: '#ea580c', secondary: '#f97316', username: '#9a3412',
                replyBg: '#fed7aa', replyBorder: '#ea580c', ownReplyBg: '#fec682', ownReplyBorder: '#f97316',
                shadow: 'rgba(234,88,12,0.08)', danger: '#ef4444', dangerHover: '#dc2626'
            },
            // 橙色夜晚 - 篝火余晖
            {
                bg: '#431407', text: '#fed7aa', chatBg: '#7c2d12', msgBg: '#9a3412', ownMsgBg: '#c2410c',
                inputBg: '#7c2d12', border: '#9a3412', accent: '#fb923c', secondary: '#fdba74', username: '#fed7aa',
                replyBg: '#9a3412', replyBorder: '#f97316', ownReplyBg: '#c2410c', ownReplyBorder: '#fb923c',
                shadow: 'rgba(0,0,0,0.5)', danger: '#f87171', dangerHover: '#ef4444'
            }
        ];
        // --- NEW Notification & Modal Functions ---
        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast-notification ${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);

            requestAnimationFrame(() => {
                toast.classList.add('show');
            });

            setTimeout(() => {
                toast.classList.add('hide');
                toast.addEventListener('transitionend', () => toast.remove(), { once: true });
            }, 3000);
        }

        function showConfirm(text, yesText = '确认', noText = '取消') {
            const modal = document.getElementById('confirmModal');
            document.getElementById('confirmModalText').textContent = text;
            const yesBtn = document.getElementById('confirmModalYes');
            const noBtn = document.getElementById('confirmModalNo');
            yesBtn.textContent = yesText;
            noBtn.textContent = noText;

            modal.classList.add('active');

            return new Promise((resolve) => {
                const yesHandler = () => {
                    closeModal(modal);
                    cleanup();
                    resolve(true);
                };
                const noHandler = () => {
                    closeModal(modal);
                    cleanup();
                    resolve(false);
                };

                const cleanup = () => {
                    yesBtn.removeEventListener('click', yesHandler);
                    noBtn.removeEventListener('click', noHandler);
                };

                yesBtn.addEventListener('click', yesHandler, { once: true });
                noBtn.addEventListener('click', noHandler, { once: true });
            });
        }

        function closeModal(modal) {
            modal.classList.add('closing');
            modal.addEventListener('animationend', () => {
                modal.classList.remove('active', 'closing');
            }, { once: true });
        }

        // --- End of New Functions ---


        // ANIMATION FIX
        function deactivateInputFocus() {
            if (!isDesktop && inputContainer.classList.contains('focused')) {
                inputFocusOverlay.classList.remove('active');
                inputContainer.classList.add('unfocusing');

                inputContainer.addEventListener('animationend', (e) => {
                    if (e.animationName === 'slideOutFromCenterToBottom') {
                        inputContainer.style.transform = ''; 
                        inputContainer.style.opacity = '0';
                        inputContainer.classList.remove('focused', 'unfocusing');
                        requestAnimationFrame(() => {
                            inputContainer.style.transition = 'opacity 0.2s';
                            inputContainer.style.opacity = '1';
                            inputContainer.addEventListener('transitionend', () => {
                                inputContainer.style.transition = '';
                                inputContainer.style.opacity = '';
                            }, { once: true });
                        });
                    }
                }, { once: true });
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            applySettings(savedSettings);
            loadInitialMessages();
            startPolling();

            if (isDesktop) {
                document.getElementById('profileBtnDesktop').addEventListener('click', () => switchTab('settings'));
                desktopUserList.addEventListener('click', handleDesktopChatSelection);
            } else {
                publicChatBtn.addEventListener('click', () => switchTab('public'));
                privateChatBtn.addEventListener('click', () => switchTab('private'));
                settingsBtn.addEventListener('click', () => switchTab('settings'));
                document.querySelectorAll('.user-item.grid-item').forEach(item => {
                    item.addEventListener('click', selectPrivateChatUserMobile);
                });
                chatSelectorModal.addEventListener('click', closeChatSelectorModal);
                
                messageInput.addEventListener('focus', () => {
                    inputContainer.classList.add('focused');
                    inputFocusOverlay.classList.add('active');
                });
                
                inputFocusOverlay.addEventListener('click', () => {
                    deactivateInputFocus();
                    messageInput.blur();
                });
            }
            updateScrollBtnPosition();

            // Initialize Highlight.js and ensure light-colored code blocks
            hljs.highlightAll();
            // Apply light color to code blocks after highlighting
            setTimeout(() => {
                const codeBlocks = document.querySelectorAll('pre code.hljs, code.hljs');
                codeBlocks.forEach(block => {
                    block.style.color = '#0f172a';
                    block.style.backgroundColor = '#ffffff';
                });
            }, 0);

            // --- Event Listeners ---
            messageInput.addEventListener('input', () => {
                resizeInput.call(messageInput);
                updateScrollBtnPosition();
            });
            sendBtn.addEventListener('click', sendMessage);
            messageInput.addEventListener('keypress', handleEnterKey);
            logoutBtn.addEventListener('click', logout);
            messagesContainer.addEventListener('scroll', handleScroll);
            scrollToBottomBtn.addEventListener('click', () => scrollToBottom(true));
            profileForm.addEventListener('submit', handleProfileUpdate);
            avatarInput.addEventListener('change', previewAvatar);
            replyCancelBtn.addEventListener('click', cancelReply);

            // --- Settings Page Event Listeners ---
            const radiusSlider = document.getElementById('radiusSlider');
            const themeOptions = document.querySelectorAll('.theme-option');
            const saveSettingsBtn = document.getElementById('saveSettingsBtn');
            const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');

            radiusSlider.addEventListener('input', () => {
                currentSettings.radius = parseInt(radiusSlider.value);
                applySettings(currentSettings);
                document.getElementById('radiusValue').textContent = currentSettings.radius + ' px';
                // Update slider background fill
                const percentage = (radiusSlider.value - radiusSlider.min) / (radiusSlider.max - radiusSlider.min) * 100;
                radiusSlider.style.backgroundSize = `${percentage}% 100%, 100% 100%`;
            });

            themeOptions.forEach(option => {
                option.addEventListener('click', () => {
                    currentSettings.theme = parseInt(option.getAttribute('data-theme'));
                    applySettings(currentSettings);
                    updateVisualSettingsControls();
                });
            });

            saveSettingsBtn.addEventListener('click', handleSettingsUpdate);
            cancelSettingsBtn.addEventListener('click', revertSettings);
            updateVisualSettingsControls();
        });

        function resizeInput() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        }

        function updateScrollBtnPosition() {
            let extraHeight = replyPreview.style.display !== 'none' ? replyPreview.offsetHeight : 0;
            if (isDesktop) {
                scrollToBottomBtn.style.bottom = `${inputContainer.offsetHeight + extraHeight + 20}px`;
            } else {
                const bottomOffset = inputContainer.offsetHeight + bottomNav.offsetHeight + extraHeight + 10;
                scrollToBottomBtn.style.bottom = `${bottomOffset}px`;
            }
        }

        function handleEnterKey(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        }

        function cancelReply() {
            replyToId = null;
            replyPreview.style.display = 'none';
            updateScrollBtnPosition();
        }
        
        function loadInitialMessages() {
            if (isPublicChat) {
                loadPublicMessages();
            } else if(selectedReceiverId) {
                loadPrivateMessages();
            }
        }

        function switchTab(tab) {
            if (currentTab === 'settings' && tab !== 'settings') {
                revertSettings(); // Revert any unsaved changes when leaving settings tab
            }

            currentTab = tab;
            document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));

            if (tab === 'public') {
                publicChatBtn.classList.add('active');
                isPublicChat = true;
                selectedReceiverId = null;
                chatSelectorModal.classList.remove('active');
                cancelReply();

                // Fade animation for container switch
                settingsContainer.classList.add('fade-out');
                chatContainer.classList.remove('fade-out', 'fade-in');
                chatContainer.style.display = 'flex';
                settingsContainer.style.display = 'none';

                requestAnimationFrame(() => {
                    chatContainer.classList.add('fade-in');
                    loadPublicMessages();
                });
            } else if (tab === 'private') {
                privateChatBtn.classList.add('active');
                isPublicChat = false;
                chatSelectorModal.classList.add('active');
                cancelReply();

                settingsContainer.classList.add('fade-out');
                chatContainer.classList.remove('fade-out', 'fade-in');
                chatContainer.style.display = 'flex';
                settingsContainer.style.display = 'none';

                requestAnimationFrame(() => {
                    chatContainer.classList.add('fade-in');
                    if(!selectedReceiverId) {
                        messagesContainer.innerHTML = '<div class="loader"><i class="fas fa-spinner fa-spin"></i> 请选择聊天对象</div>';
                    } else {
                        // 如果已经选择了私聊对象,重新加载消息
                        loadPrivateMessages();
                    }
                });
            } else if (tab === 'settings') {
                if (settingsBtn) settingsBtn.classList.add('active');

                chatContainer.classList.add('fade-out');
                settingsContainer.classList.remove('fade-out', 'fade-in');
                settingsContainer.style.display = 'flex';
                chatContainer.style.display = 'none';

                requestAnimationFrame(() => {
                    settingsContainer.classList.add('fade-in');
                });
            }
        }

        function selectPrivateChatUserMobile() {
            selectedReceiverId = this.getAttribute('data-user-id');
            chatSelectorModal.classList.remove('active');
            cancelReply();
            loadPrivateMessages();
        }

        function handleDesktopChatSelection(e) {
            const userItem = e.target.closest('.user-item');
            if (!userItem) return;

            if (currentTab === 'settings') {
                revertSettings();
            }

            document.querySelectorAll('#desktopUserList .user-item').forEach(item => item.classList.remove('active'));
            userItem.classList.add('active');

            currentTab = 'chat'; // Generic chat tab for desktop
            const chatType = userItem.getAttribute('data-chat-type');
            cancelReply();

            settingsContainer.classList.add('fade-out');
            chatContainer.classList.remove('fade-out', 'fade-in');
            chatContainer.style.display = 'flex';
            settingsContainer.style.display = 'none';

            if (chatType === 'public') {
                isPublicChat = true;
                selectedReceiverId = null;
                requestAnimationFrame(() => {
                    chatContainer.classList.add('fade-in');
                    loadPublicMessages();
                });
            } else if (chatType === 'private') {
                isPublicChat = false;
                selectedReceiverId = userItem.getAttribute('data-user-id');
                requestAnimationFrame(() => {
                    chatContainer.classList.add('fade-in');
                    loadPrivateMessages();
                });
            }
        }

        function closeChatSelectorModal(e) {
            if (e.target === chatSelectorModal) {
                chatSelectorModal.classList.add('closing');
                chatSelectorModal.addEventListener('animationend', () => {
                    chatSelectorModal.classList.remove('active', 'closing');
                }, { once: true });
            }
        }

        async function logout() {
            const confirmed = await showConfirm('确定要退出登录吗？', '退出', '取消');
            if (confirmed) {
                window.location.href = 'logout.php';
            }
        }

        function handleScroll() {
            const isAtBottom = messagesContainer.scrollHeight - messagesContainer.scrollTop <= messagesContainer.clientHeight + 100;
            scrollToBottomBtn.classList.toggle('visible', !isAtBottom);
        }

        function scrollToBottom(smooth = false) {
            messagesContainer.scrollTo({ top: messagesContainer.scrollHeight, behavior: smooth ? 'smooth' : 'auto' });
        }

        function handleProfileUpdate(e) {
            e.preventDefault();
            const formData = new FormData(profileForm);
            formData.append('action', 'update_profile');

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showToast('个人信息更新成功');
                    profileAvatar.src = data.new_avatar;
                    document.getElementById('profileUsername').textContent = data.new_username;
                } else {
                    showToast('更新失败: ' + data.message, 'error');
                }
            })
            .catch(error => console.error('Error:', error));
        }

        function previewAvatar(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    profileAvatar.src = event.target.result;
                    document.getElementById('fileName').textContent = file.name;
                };
                reader.readAsDataURL(file);
            }
        }

        async function sendMessage() {
            const message = messageInput.value.trim();
            if (!message) return;

            if (isPublicChat) {
                sendPublicMessage(message);
            } else if (selectedReceiverId) {
                sendPrivateMessage(message, selectedReceiverId);
            } else {
                showToast('请先选择聊天对象', 'error');
            }

            messageInput.value = '';
            resizeInput.call(messageInput);
            cancelReply();
            deactivateInputFocus();
        }

        function sendPublicMessage(message) {
            const formData = new FormData();
            formData.append('action', 'send_message');
            formData.append('message', message);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');
            if (replyToId) formData.append('reply_to', replyToId);

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    appendMessage(data.new_message, true);
                } else {
                    showToast('发送失败: ' + data.message, 'error');
                }
            })
            .catch(error => console.error('Error:', error));
        }

        function sendPrivateMessage(message, receiverId) {
            const formData = new FormData();
            formData.append('action', 'send_private_message');
            formData.append('private_message', message);
            formData.append('receiver_id', receiverId);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');
            if (replyToId) formData.append('reply_to', replyToId);

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                if(data.success) {
                    appendMessage(data.new_message, true);
                } else {
                    showToast('发送失败: ' + data.message, 'error');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function loadPublicMessages() {
            messagesContainer.innerHTML = '<div class="loader"><i class="fas fa-spinner fa-spin"></i> 加载中...</div>';
            fetch('index.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_messages&csrf_token=<?php echo $_SESSION['csrf_token']; ?>'
            })
            .then(res => res.json())
            .then(data => data.success ? displayInitialMessages(data.messages) : (messagesContainer.innerHTML = `<div class="loader">加载失败: ${data.message}</div>`))
            .catch(err => messagesContainer.innerHTML = '<div class="loader">加载失败，请重试</div>');
        }

        function loadPrivateMessages() {
            if (!selectedReceiverId) return;
            messagesContainer.innerHTML = '<div class="loader"><i class="fas fa-spinner fa-spin"></i> 加载中...</div>';
            const formData = new FormData();
            formData.append('action', 'get_private_messages');
            formData.append('receiver_id', selectedReceiverId);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => data.success ? displayInitialMessages(data.messages) : (messagesContainer.innerHTML = `<div class="loader">加载失败: ${data.message}</div>`))
            .catch(err => messagesContainer.innerHTML = '<div class="loader">加载失败，请重试</div>');
        }

        function displayInitialMessages(messages) {
            messagesContainer.innerHTML = '';
            latestPublicTimestamp = 0;
            latestPrivateTimestamp = 0;
            if (messages.length === 0) {
                messagesContainer.innerHTML = '<div class="loader" style="animation: fadeIn 0.5s ease;">暂无消息</div>';
                return;
            }
            messages.reverse();
            messages.forEach((msg, index) => {
                const el = createMessageElement(msg);
                el.style.animation = 'none';
                messagesContainer.appendChild(el);
                updateLatestTimestamp(msg.timestamp);
            });
            setTimeout(() => {
                scrollToBottom(false);
                if (typeof MathJax !== 'undefined') MathJax.typesetPromise();
                if (typeof hljs !== 'undefined') {
                    hljs.highlightAll();
                    // Apply light color to code blocks after highlighting
                    setTimeout(() => {
                        const codeBlocks = document.querySelectorAll('pre code.hljs, code.hljs');
                        codeBlocks.forEach(block => {
                            block.style.color = '#0f172a';
                            block.style.backgroundColor = '#ffffff';
                        });
                    }, 0);
                }
            }, 50);
        }

        function createMessageElement(msg) {
            const el = document.createElement('div');
            el.className = 'message';
            el.dataset.messageId = msg.id; 
            if (msg.user_id === currentUserId || msg.sender_id === currentUserId) el.classList.add('own');
            
            const replyHtml = msg.reply_to ? `<div class="reply-preview"><span><strong>回复 ${msg.reply_to.username}:</strong> ${msg.reply_to.message}</span></div>` : '';
            const avatarUrl = msg.avatar || msg.sender_avatar || 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"%3E%3Ccircle cx="50" cy="50" r="50" fill="%23e2e8f0"/%3E%3Ccircle cx="50" cy="35" r="18" fill="%2394a3b8"/%3E%3Cpath d="M 20 85 Q 20 60 50 60 Q 80 60 80 85 Z" fill="%2394a3b8"/%3E%3C/svg%3E';
            const username = msg.username || msg.sender_username;

            el.innerHTML = `
                ${replyHtml}
                <div class="message-header">
                    <img src="${avatarUrl}" class="avatar" style="${isPublicChat ? 'display: none;' : ''}">
                    <span class="username">${username}</span>
                    <span class="timestamp">${formatTime(msg.timestamp)}</span>
                </div>
                <div class="message-content">${msg.message}</div>
            `;
            el.addEventListener('contextmenu', e => {
                e.preventDefault();
                showContextMenu(e, msg.id, msg.sender_id === undefined);
            });
            return el;
        }

        function appendMessage(msg, isOwnMessage = false) {
            if (document.querySelector(`.message[data-message-id="${msg.id}"]`)) return;
            if (messagesContainer.querySelector('.loader')) messagesContainer.innerHTML = '';

            const shouldScroll = isOwnMessage || (messagesContainer.scrollHeight - messagesContainer.scrollTop <= messagesContainer.clientHeight + 150);
            const el = createMessageElement(msg);

            // Add staggered animation for new messages
            el.style.animation = `messageAppear 0.4s cubic-bezier(0.25, 0.8, 0.25, 1) forwards`;
            messagesContainer.appendChild(el);
            updateLatestTimestamp(msg.timestamp);

            if (shouldScroll) scrollToBottom(true);
            if (typeof MathJax !== 'undefined') MathJax.typesetPromise([el.querySelector('.message-content')]);
            if (typeof hljs !== 'undefined') {
                hljs.highlightAll();
                // Apply light color to code blocks after highlighting
                setTimeout(() => {
                    const codeBlocks = el.querySelectorAll('pre code.hljs, code.hljs');
                    codeBlocks.forEach(block => {
                        block.style.color = '#0f172a';
                        block.style.backgroundColor = '#ffffff';
                    });
                }, 0);
            }
        }
        
        function updateLatestTimestamp(timestamp) {
            if (isPublicChat) {
                if (timestamp > latestPublicTimestamp) latestPublicTimestamp = timestamp;
            } else {
                if (timestamp > latestPrivateTimestamp) latestPrivateTimestamp = timestamp;
            }
        }

        function formatTime(timestamp) {
            if (!timestamp) return '未知时间';
            const date = new Date(timestamp * 1000);
            const now = new Date();
            const diff = (now - date) / 1000;
            if (diff < 60) return '刚刚';
            if (diff < 3600) return `${Math.floor(diff / 60)}分钟前`;

            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const msgDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
            const timeDiffDays = (today - msgDate) / 86400000;
            const timeString = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
            if (timeDiffDays < 1) return timeString;
            if (timeDiffDays < 2) return `昨天 ${timeString}`;
            return `${date.getFullYear()}/${date.getMonth() + 1}/${date.getDate()}`;
        }
        
        function startPolling() {
            if (pollingInterval) clearInterval(pollingInterval);
            pollingInterval = setInterval(pollNewMessages, 3000);
        }

        function pollNewMessages() {
            const formData = new FormData();
            formData.append('action', 'check_new_messages');
            formData.append('lastPublicTimestamp', latestPublicTimestamp);
            formData.append('lastPrivateTimestamp', latestPrivateTimestamp);
            formData.append('currentReceiverId', selectedReceiverId || 0);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    if (data.newPublicMessages.length > 0 && isPublicChat) data.newPublicMessages.forEach(msg => appendMessage(msg));
                    if (data.newPrivateMessages.length > 0 && !isPublicChat && selectedReceiverId) data.newPrivateMessages.forEach(msg => appendMessage(msg));
                }
            })
            .catch(error => console.error('Error polling messages:', error));
        }

        async function showContextMenu(event, messageId, isPublic) {
            document.querySelectorAll('.context-menu').forEach(menu => menu.remove());
            const menu = document.createElement('div');
            menu.className = 'context-menu';
            menu.innerHTML = `<div class="context-item" data-action="reply">回复</div><div class="context-item" data-action="recall">撤回</div>`;
            document.body.appendChild(menu);

            let x = event.clientX, y = event.clientY;
            if ((x + menu.offsetWidth) > window.innerWidth) x = window.innerWidth - menu.offsetWidth - 5;
            if ((y + menu.offsetHeight) > window.innerHeight) y = window.innerHeight - menu.offsetHeight - 5;
            menu.style.left = `${x}px`;
            menu.style.top = `${y}px`;

            menu.addEventListener('click', async (e) => {
                const item = e.target.closest('.context-item');
                if (!item) return;
                const action = item.dataset.action;
                if (action === 'reply') {
                    replyToId = messageId;
                    const msgEl = messagesContainer.querySelector(`[data-message-id="${messageId}"]`);
                    if (msgEl) {
                        replyPreviewContent.innerHTML = `<strong>回复 ${msgEl.querySelector('.username').textContent}:</strong> ${msgEl.querySelector('.message-content').innerHTML}`;
                        replyPreview.style.display = 'flex';
                        messageInput.focus();
                        updateScrollBtnPosition();
                    }
                } else if (action === 'recall') {
                    const confirmed = await showConfirm('确定要撤回这条消息吗？', '撤回', '取消');
                    if (confirmed) {
                         recallMessage(messageId, isPublic);
                    }
                }
                menu.remove();
            });
            setTimeout(() => document.addEventListener('click', () => menu.remove(), { once: true }), 0);
        }

        function recallMessage(messageId, isPublic) {
            const formData = new FormData();
            formData.append('action', 'recall_message');
            formData.append('message_id', messageId);
            formData.append('is_private', !isPublic);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const el = messagesContainer.querySelector(`[data-message-id="${messageId}"]`);
                    if (el) {
                        // Smooth remove animation
                        el.style.animation = 'slideOutToBottom 0.3s cubic-bezier(0.4, 0, 1, 1) forwards';
                        el.addEventListener('animationend', () => el.remove(), { once: true });
                    }
                } else {
                    showToast('撤回失败: ' + data.message, 'error');
                }
            })
            .catch(error => console.error('Error:', error));
        }

        // --- Settings Functions ---
        
        function handleSettingsUpdate() {
            const formData = new FormData();
            formData.append('action', 'save_settings');
            formData.append('theme', currentSettings.theme);
            formData.append('radius', currentSettings.radius);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');

            fetch('index.php', { method: 'POST', body: formData })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showToast('设置保存成功');
                    savedSettings = JSON.parse(JSON.stringify(currentSettings));
                } else {
                    showToast('保存失败', 'error');
                    revertSettings(); // Revert on failure
                }
            })
            .catch(error => console.error('Error:', error));
        }

        function revertSettings() {
            currentSettings = JSON.parse(JSON.stringify(savedSettings));
            applySettings(currentSettings);
            updateVisualSettingsControls();
        }

        function updateVisualSettingsControls() {
            // Update slider
            const radiusSlider = document.getElementById('radiusSlider');
            radiusSlider.value = currentSettings.radius;
            document.getElementById('radiusValue').textContent = currentSettings.radius + ' px';
            // Update slider background fill
            const percentage = (currentSettings.radius - radiusSlider.min) / (radiusSlider.max - radiusSlider.min) * 100;
            radiusSlider.style.backgroundSize = `${percentage}% 100%, 100% 100%`;

            // Update theme selector
            document.querySelectorAll('.theme-option').forEach(opt => {
                opt.classList.toggle('active', parseInt(opt.getAttribute('data-theme')) === currentSettings.theme);
            });
        }

        function applySettings(settings) {
            const theme = themes[settings.theme];
            const root = document.documentElement;
            const propertyMap = {
                '--bg-color': theme.bg,
                '--text-color': theme.text,
                '--chat-bg': theme.chatBg,
                '--msg-bg': theme.msgBg,
                '--own-msg-bg': theme.ownMsgBg,
                '--input-bg': theme.inputBg,
                '--border-color': theme.border,
                '--accent-color': theme.accent,
                '--secondary-text': theme.secondary,
                '--username-color': theme.username,
                '--reply-bg': theme.replyBg,
                '--reply-border': theme.replyBorder,
                '--own-reply-bg': theme.ownReplyBg,
                '--own-reply-border': theme.ownReplyBorder,
                '--shadow-color': theme.shadow,
                '--danger-color': theme.danger,
                '--danger-color-hover': theme.dangerHover,
                '--border-radius-msg': `${settings.radius}px`,
            };
            for (const prop in propertyMap) {
                root.style.setProperty(prop, propertyMap[prop]);
            }
            
            // Ensure code blocks are always light-colored
            const codeBlocks = document.querySelectorAll('pre code.hljs, code.hljs');
            codeBlocks.forEach(block => {
                block.style.color = '#0f172a';
                block.style.backgroundColor = '#ffffff';
            });
            
            // Update slider background fill
            const radiusSlider = document.getElementById('radiusSlider');
            if (radiusSlider) {
                const percentage = (settings.radius - radiusSlider.min) / (radiusSlider.max - radiusSlider.min) * 100;
                radiusSlider.style.backgroundSize = `${percentage}% 100%, 100% 100%`;
            }
        }
    </script>
</div>
</body>
</html>