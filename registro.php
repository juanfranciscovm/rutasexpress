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
            //conectar a la base de datos
            require_once 'config/conexion.php';

            //verificar si el email ya existe en la tabla 'usuarios'
            $stmt = $pdo->prepare("SELECT id_usuario FROM usuarios WHERE email = ?");
            $stmt->execute([$email]);

            if ($stmt->fetch()) {
                $error = 'Este correo electrónico ya está registrado.';
            } else {
                //cifrar la contraseña con password_hash()
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $idRolDefault = 1; //rol 1 asignado a usuarios nuevos
                $twoFaActivo  = 0; //2FA inactivo por defecto al registrarse

                //insertar el nuevo usuario en la tabla 'usuarios'
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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="registro.css">
</head>
<body>

<div class="split-layout">
    <aside class="left-panel">
        <img class="brand-logo" src="assets/LOGO CORTO BLANCO 3.1.svg" alt="Rutas Express">

        <div class="hero-text">
            <h1>¡Bienvenido a<br>Rutas<br>Express!</h1>
            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vulputate ut laoreet velit ma.</p>
        </div>

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
                    <input
                        type="text"
                        id="nombre"
                        name="nombre"
                        required
                        placeholder="Introduce tu nombre"
                        value="<?= htmlspecialchars($_POST['nombre'] ?? '') ?>"
                    >
                </div>

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
                    <input
                        type="password"
                        id="password"
                        name="password"
                        minlength="8"
                        required
                        placeholder="Introduce tu contraseña"
                    >
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
                <img width="15" height="15" src="assets/google.png" >
                Iniciar sesión con Google
            </button>
        </div>

        <p class="bottom-text">
            ¿Ya tienes cuenta? <a href="login.php">Inicia sesión</a>
        </p>
    </main>
</div>

</body>
</html>