<?php

namespace App\Http\Middleware;

use App\Models\Guardians;
use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;

class GuardianJWT
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            // Autentica usando el guard 'guardian'
            $user = Auth::guard('guardian')->user();

            // Si no hay usuario, intenta con JWTAuth
            if (!$user) {
                $user = JWTAuth::parseToken()->authenticate();
            }

            // Verifica que sea instancia de Guardians
            if (!$user || !($user instanceof Guardians)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Solo los tutores pueden acceder a este recurso.',
                    'instance_type' => $user ? get_class($user) : null,
                    'timestamp' => now(),
                ], 403);
            }

            $request->merge(['guardian' => $user]);

            return $next($request);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token inválido o tutor no autenticado.',
                'timestamp' => now(),
            ], 401);
        }
    }
}
