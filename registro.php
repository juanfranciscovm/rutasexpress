<?php
session_start();

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['nombre'] ?? '');
    $email    = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $password = trim($_POST['password'] ?? '');
    $terminos = isset($_POST['terminos']);

    if (empty($username) || empty($email) || empty($password)) {
        $error = 'Todos los campos son obligatorios.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Introduce un correo electrónico válido.';
    } elseif (strlen($password) < 8) {
        $error = 'La contraseña debe tener al menos 8 caracteres.';
    } elseif (!$terminos) {
        $error = 'Debes aceptar los términos y condiciones.';
    } else {
        try {
            require_once 'config/conexion.php';

            $stmt = $pdo->prepare("SELECT id_usuario FROM usuarios WHERE email = ?");
            $stmt->execute([$email]);

            if ($stmt->fetch()) {
                $error = 'Este correo electrónico ya está registrado.';
            } else {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $idRolDefault = 1;
                $twoFaActivo  = 0;

                $insert = $pdo->prepare(
                    "INSERT INTO usuarios (username, email, password_hash, 2FA_activo, id_rol) 
                     VALUES (?, ?, ?, ?, ?)"
                );
                $insert->execute([$username, $email, $passwordHash, $twoFaActivo, $idRolDefault]);

                session_regenerate_id(true);
                $_SESSION['loggedin']   = true;
                $_SESSION['user_id']    = $pdo->lastInsertId();
                $_SESSION['username']   = $username;
                $_SESSION['user_email'] = $email;
                $_SESSION['id_rol']     = $idRolDefault;
                $_SESSION['login_time'] = time();

                header('Location: index.php');
                exit();
            }
        } catch (PDOException $e) {
            $error = 'Error SQL: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crea tu cuenta — Rutas Express</title>
    <link rel="stylesheet" href="assets/css/theme.css?v=<?= time() ?>">
    <link rel="stylesheet" href="registro.css?v=<?= time() ?>">
</head>
<body>

<div class="split-layout">
    <aside class="left-panel">
        <img class="brand-logo" src="assets/LOGO CORTO BLANCO 3.1.svg" alt="Rutas Express">

        <div class="hero-text">
            <h1>¡Bienvenido a<br>Rutas Express!</h1>
            <p>Regístrate y viaja con nosotros.</p>
        </div>

        <img class="bus-img" src="assets/bus.png" alt="Autobús Rutas Express">
    </aside>

    <main class="right-panel">
        <div class="form-container">
            <div class="form-header">
                <h2>Crea tu cuenta</h2>
                <p>Es gratis y fácil</p>
            </div>

            <?php if ($error): ?>
                <div class="alert-error">
                    <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form method="post" action="registro.php">
                <div class="form-group">
                    <label for="nombre">Nombre completo</label>
                    <div class="input-wrapper">
                        <span class="material-symbols-rounded input-icon">person</span>
                        <input
                            type="text"
                            id="nombre"
                            name="nombre"
                            required
                            placeholder="Introduce tu nombre"
                            value="<?= htmlspecialchars($_POST['nombre'] ?? '') ?>"
                        >
                    </div>
                </div>

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
                            minlength="8"
                            required
                            placeholder="Introduce tu contraseña"
                        >
                        <button type="button" class="toggle-password" onclick="togglePass()" aria-label="Mostrar contraseña">
                            <span class="material-symbols-rounded" id="eyeIcon">visibility_off</span>
                        </button>
                    </div>
                    <span class="helper-text">Debe tener al menos 8 caracteres</span>
                </div>

                <div class="terms-group">
                    <input type="checkbox" id="terminos" name="terminos" required>
                    <label for="terminos">
                        Al crear una cuenta, aceptas los <strong>Términos y Condiciones</strong>, y nuestra <strong>Política de privacidad</strong>
                    </label>
                </div>

                <button type="submit" class="btn-submit">Registrarse</button>
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
            ¿Ya tienes cuenta? <a href="login.php">Inicia sesión</a>
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
