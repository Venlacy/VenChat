<?php
// VenlanChat 配置文件
return [
    // 数据库配置
    'db' => [
        'host' => '',
        'user' => '',
        'pass' => '',
        'name' => '',
        'charset' => 'utf8mb4'
    ],
    
    // 消息相关配置
    'db_file' => 'data/messages.json',
    'log_file' => 'data/log.txt',
    'max_messages' => 100,
    'message_max_length' => 50000,
    'rate_limit' => 50,
    
    // 安全配置
    'admin_password' => 'admin123', // 仍保留用于管理员面板
    'enable_admin_delete' => true,
    'enable_rate_limit' => true,
    'enable_access_log' => true,
    'enable_emoji' => true,
    
    // 站点配置
    'site_title' => 'VenlanChat',
    'site_description' => '实时聊天室',
    
    // 显示配置
    'auto_refresh_interval' => 5000,
    'show_timestamp' => true,
    'show_ip_to_admin' => true,
    
    // 文件上传配置
    'enable_file_upload' => false,
    'max_file_size' => 1048576,
    'allowed_file_types' => ['jpg', 'jpeg', 'png', 'gif'],
    
    // 系统配置
    'timezone' => 'Asia/Shanghai',
    'date_format' => 'Y-m-d H:i:s',
    
    // 主题配置
    'theme' => [
        'primary_color' => '#667eea',
        'secondary_color' => '#764ba2',
        'background_type' => 'gradient',
        'custom_css' => '',
    ],
    
    // 版本信息
    'version' => '2.0',
    'build_date' => '2024-01-01',
];
?>
