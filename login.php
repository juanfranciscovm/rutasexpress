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
            require_once 'config/puente.php';

            $stmt = $pdo->prepare(
                "SELECT id_usuario, username, email, password_hash, id_rol, 2FA_activo 
                 FROM usuarios WHERE email = ?"
            );
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password_hash'])) {
                session_regenerate_id(true);

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
    <title>Iniciar sesión — Rutas Express</title>
    <link rel="stylesheet" href="assets/css/theme.css?v=<?= time() ?>">
    <link rel="stylesheet" href="login.css?v=<?= time() ?>">
</head>
<body>

<div class="split-layout">
    <aside class="left-panel">
        <img class="brand-logo" src="assets/LOGO CORTO BLANCO 3.1.svg" alt="Rutas Express">

        <div class="hero-text">
            <h1>¡Bienvenido a<br>Rutas Express!</h1>
            <p>Viaja seguro y al mejor precio.</p>
        </div>

        <img class="bus-img" src="assets/bus.png" alt="Autobús Rutas Express">
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
                    <div class="input-wrapper">
                        <span class="material-symbols-rounded input-icon">mail</span>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            required
                            placeholder="Introduce tu correo o teléfono"
                            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="password">Contraseña</label>
                    <div class="input-wrapper password-wrapper">
                        <span class="material-symbols-rounded input-icon">lock</span>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            required
                            placeholder="Introduce tu contraseña"
                        >
                        <button type="button" class="toggle-password" onclick="togglePass()" aria-label="Mostrar contraseña">
                            <span class="material-symbols-rounded" id="eyeIcon">visibility_off</span>
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
                <img width="16" height="16" src="assets/google.png" alt="Google">
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
    const eye = document.getElementById('eyeIcon');
    if (input.type === 'password') {
        input.type = 'text';
        if (eye) eye.textContent = 'visibility';
    } else {
        input.type = 'password';
        if (eye) eye.textContent = 'visibility_off';
    }
}
</script>

</body>
</html>
