<?php
session_start();
require_once 'db_connect.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $mysqli = get_db_connection();
    $stmt = $mysqli->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        if (password_verify($password, $row['password'])) {
            // 防止会话固定攻击 - 重新生成会话ID
            session_regenerate_id(true);
            $_SESSION['user_id'] = $row['id'];
            header('Location: index.php');
            exit;
        }
    }
    $stmt->close();
    $mysqli->close();
    $error = "用户名或密码错误";
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - VenlanChat</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-color: #eef1f5;
            --text-color: #1a202c;
            --input-bg: #ffffff;
            --border-color: #e2e8f0;
            --accent-color: #4299e1;
            --danger-color: #e53e3e;
            --shadow-color: rgba(0,0,0,0.05);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            background: var(--input-bg);
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 4px 20px var(--shadow-color);
            max-width: 400px;
            width: 100%;
        }

        h2 {
            text-align: center;
            margin-bottom: 30px;
            color: var(--text-color);
            font-size: 1.75rem;
            font-weight: 600;
        }

        .form-group {
            margin-bottom: 20px;
            position: relative;
        }

        .form-group i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--accent-color);
        }

        input {
            width: 100%;
            padding: 12px 12px 12px 40px;
            border: 1px solid var(--border-color);
            border-radius: 24px;
            background: var(--input-bg);
            font-size: 16px;
            transition: border-color 0.3s, box-shadow 0.3s;
        }

        input:focus {
            outline: none;
            border-color: var(--accent-color);
            box-shadow: 0 0 5px rgba(66, 153, 225, 0.3);
        }

        .error {
            color: var(--danger-color);
            font-size: 14px;
            text-align: center;
            margin-bottom: 15px;
            padding: 10px;
            background: #fff5f5;
            border-radius: 8px;
        }

        button {
            width: 100%;
            padding: 12px;
            background: var(--accent-color);
            color: white;
            border: none;
            border-radius: 24px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        button:hover {
            background: #3182ce;
        }

        .link {
            text-align: center;
            margin-top: 15px;
        }

        .link a {
            color: var(--accent-color);
            text-decoration: none;
            font-size: 14px;
        }

        .link a:hover {
            text-decoration: underline;
        }

        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
            }
            h2 {
                font-size: 1.5rem;
            }
            input, button {
                font-size: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>登录 VenlanChat</h2>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="POST">
            <div class="form-group">
                <i class="fas fa-user"></i>
                <input type="text" name="username" placeholder="用户名" required>
            </div>
            <div class="form-group">
                <i class="fas fa-lock"></i>
                <input type="password" name="password" placeholder="密码" required>
            </div>
            <button type="submit">登录</button>
            <div class="link">
                <a href="register.php">没有账户？立即注册</a>
            </div>
        </form>
    </div>
</body>
</html>