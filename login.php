<?php
session_start();

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $password = trim($_POST['password'] ?? '');

    if (empty($email) || empty($password)) {
        $error = 'Por favor completa todos los campos.';
    } else {
        try {
            //conectar a la base de datos
            require_once 'config/conexion.php';

            //buscar el usuario en la tabla usuarios
            $stmt = $pdo->prepare(
                "SELECT id_usuario, username, email, password_hash, id_rol, 2FA_activo 
                 FROM usuarios WHERE email = ?"
            );
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            //verificar contraseña
            if ($user && password_verify($password, $user['password_hash'])) {
                session_regenerate_id(true);

                //guardar sesión con las columnas de la bdd
                $_SESSION['loggedin']   = true;
                $_SESSION['user_id']    = $user['id_usuario'];
                $_SESSION['username']   = $user['username'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['id_rol']     = $user['id_rol'];
                $_SESSION['login_time'] = time();

                header('Location: index.php');
                exit();

            } else {
                $error = 'Credenciales inválidas';
            }
        } catch (PDOException $e) {
            $error = 'Error de conexión con el servidor.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Iniciar sesión</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="login.css">
</head>
<body>

<div class="split-layout">
    <aside class="left-panel">
        <svg class="brand-logo" viewBox="0 0 100 60" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M5 35C25 32 45 30 75 48" stroke="white" stroke-width="3" stroke-linecap="round"/>
            <path d="M10 42C30 40 48 40 68 52" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
            <path d="M18 48C32 47 45 48 58 55" stroke="white" stroke-width="2" stroke-linecap="round"/>
            <path d="M25 22C50 12 72 10 85 16C90 19 93 28 92 38C91 44 85 46 78 44C62 36 45 28 25 22Z" stroke="white" stroke-width="3" fill="#2c303a"/>
            <path d="M72 16L86 20C88 24 88 30 86 34L73 30C71 25 71 20 72 16Z" fill="white"/>
            <path d="M35 20L65 16L66 26L38 24Z" fill="white"/>
        </svg>

        <div class="hero-text">
            <h1>¡Bienvenido a<br>Rutas<br>Express!</h1>
            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vulputate ut laoreet velit ma.</p>
        </div>

        <div class="illustration-card">
            <svg width="120" height="90" viewBox="0 0 120 90" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="32" cy="24" r="10" fill="#2c303a"/>
                <path d="M8 78L42 38L68 65L84 46L112 78H8Z" fill="#2c303a"/>
            </svg>
        </div>
    </aside>

    <main class="right-panel">
        <div class="form-container">
            <div class="form-header">
                <h2>¡Hola de nuevo!</h2>
                <p>Busca tu mejor destino al mejor precio</p>
            </div>

            <?php if ($error): ?>
                <div class="alert-error">
                    <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form method="post" action="login.php">
                <div class="form-group">
                    <label for="email">Correo electrónico o teléfono</label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        required
                        placeholder="Introduce tu correo o teléfono"
                        value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                    >
                </div>

                <div class="form-group">
                    <label for="password">Contraseña</label>
                    <div class="input-wrapper">
                        <input
                            type="password"
                            id="password"
                            name="password"
                            required
                            placeholder="Introduce tu contraseña"
                        >
                        <button type="button" class="toggle-password" onclick="togglePass()" aria-label="Mostrar contraseña">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                                <line x1="1" y1="1" x2="23" y2="23"/>
                            </svg>
                        </button>
                    </div>
                    <a href="#" class="forgot-link">¿Olvidaste tu contraseña?</a>
                </div>

                <button type="submit" class="btn-submit">Iniciar sesión</button>
            </form>

            <div class="divider">
                <span>o accede con otra cuenta</span>
            </div>

            <button type="button" class="btn-google">
                <svg width="15" height="15" viewBox="0 0 24 24">
                    <path fill="#1e232a" d="M21.35 11.1h-9.17v2.73h6.51c-.33 3.81-3.5 5.44-6.5 5.44C8.36 19.27 5 16.25 5 12c0-4.1 3.2-7.27 7.2-7.27 3.09 0 4.9 1.97 4.9 1.97L19 4.72S16.56 2 12.1 2C6.42 2 2.03 6.8 2.03 12c0 5.05 4.13 10 10.22 10 5.35 0 9.25-3.67 9.25-9.09 0-1.15-.15-1.81-.15-1.81Z"/>
                </svg>
                Iniciar sesión con Google
            </button>
        </div>

        <p class="bottom-text">
            ¿No tienes cuenta? <a href="registro.php">Regístrate</a>
        </p>
    </main>
</div>

<script>
function togglePass() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}
</script>

</body>
</html>