<?php

namespace App\Http\Controllers;

use App\Models\AuthorizedPeople;
use App\Models\StudentAuthorized;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthorizedPeopleController extends Controller
{
    public function create(Request $request, $studentId)
    {
        $validator = Validator::make($request->all(), [
            'firstName'    => 'required|string|max:50',
            'lastName'     => 'required|string|max:50',
            'phone'        => 'required|string|max:10',
            'relationship' => 'required|string|max:50',
            'photo'        => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Datos inválidos para crear persona autorizada',
                'errors'  => $validator->errors(),
                'timestamp' => now(),
            ], 400);
        }

        $authPerson = AuthorizedPeople::create($validator->validated());

        StudentAuthorized::create([
            'studentId' => $studentId,
            'authorizedId' => $authPerson->id,
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada creada y relacionada correctamente',
            'data'    => $authPerson,
            'timestamp' => now(),
        ], 201);
    }

    public function show($id)
    {
        $authPerson = AuthorizedPeople::find($id);

        if (!$authPerson) {
            return response()->json([
                'success' => false,
                'message' => 'Persona autorizada no encontrada',
                'timestamp' => now(),
            ], 404);
        }

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada encontrada',
            'data'    => $authPerson,
            'timestamp' => now(),
        ]);
    }

    public function edit(Request $request, $id)
    {
        $authPerson = AuthorizedPeople::find($id);

        if (!$authPerson) {
            return response()->json([
                'success' => false,
                'message' => 'Persona autorizada no encontrada',
                'timestamp' => now(),
            ], 404);
        }

        $validator = Validator::make($request->all(), [
            'firstName'    => 'sometimes|required|string|max:50',
            'lastName'     => 'sometimes|required|string|max:50',
            'phone'        => 'sometimes|required|string|max:10',
            'relationship' => 'sometimes|required|string|max:50',
            'photo'        => 'sometimes|required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Datos inválidos para editar persona autorizada',
                'errors'  => $validator->errors(),
                'timestamp' => now(),
            ], 400);
        }

        $authPerson->update($validator->validated());

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada actualizada correctamente',
            'data'    => $authPerson,
            'timestamp' => now(),
        ]);
    }

    public function delete($id)
    {
        $authPerson = AuthorizedPeople::find($id);

        if (!$authPerson) {
            return response()->json([
                'success' => false,
                'message' => 'Persona autorizada no encontrada',
                'timestamp' => now(),
            ], 404);
        }

        $authPerson->update(['status' => false]);

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada eliminada correctamente',
            'timestamp' => now(),
        ]);
    }

    public function myAuthorizeds()
    {
        // xd
    }

    public function index()
    {
        // xd
    }
}
