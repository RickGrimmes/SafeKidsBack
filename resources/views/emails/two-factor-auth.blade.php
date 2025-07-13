<!DOCTYPE html>
<html>
<head>
    <title>Código de verificación de 2 pasos</title>
</head>
<body>
    <h1>SafeKids - 2FA Method</h1>
    <p>Hola {{ $user->firstName }},</p>
    <p>Tu código de verificación para continuar con tu inicio de sesión es: <strong>{{ $code }}</strong></p>
    <p>Este código expira en 15 minutos.</p>
</body>
</html>