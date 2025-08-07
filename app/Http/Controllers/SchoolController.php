<?php

namespace App\Http\Controllers;

use App\Models\Schools;
use App\Models\SchoolTypes;
use App\Models\SchoolUsers;
use App\Models\UserRole;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class SchoolController extends Controller
{
    public function index()
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            
            if (!$userRole || !in_array($userRole->roleId, [2])) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para ver las escuelas',
                    'timestamp' => now(),
                ], 403);
            }

            $schools = Schools::with(['schoolTypes', 'schoolUsers'])
                ->where('status', true)
                ->whereHas('schoolUsers', function($query) use ($userRole) {
                    $query->where('userRoleId', $userRole->id);
                })
                ->get();

            if ($schools->isEmpty()) {
                return response()->json([
                    'success' => true,
                    'message' => 'No has creado ninguna escuela aún',
                    'data' => [],
                    'user_info' => [
                        'user_role_id' => $userRole->id,
                        'user_id' => $authenticatedUser->id,
                        'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName
                    ],
                    'timestamp' => now(),
                ], 200);
            }

            $schoolsData = $schools->map(function ($school) use ($userRole) {
                $types = $school->schoolTypes->map(function ($schoolType) {
                    return [
                        'id' => $schoolType->id,
                        'type' => $schoolType->type,
                        'type_name' => $this->getTypeName($schoolType->type)
                    ];
                });

                // Encontrar el registro school_user correspondiente
                $schoolUser = $school->schoolUsers->where('userRoleId', $userRole->id)->first();

                return [
                    'id' => $school->id,
                    'name' => $school->name,
                    'address' => $school->address,
                    'phone' => $school->phone,
                    'city' => $school->city,
                    'status' => $school->status,
                    'created_at' => $school->created_at,
                    'school_types' => $types,
                    'total_types' => $types->count(),
                    'ownership_info' => [
                        'school_user_id' => $schoolUser ? $schoolUser->id : null,
                        'user_role_id' => $userRole->id,
                        'is_owner' => true
                    ]
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Tus escuelas encontradas exitosamente',
                'data' => $schoolsData,
                'total_schools' => $schools->count(),
                'user_info' => [
                    'user_id' => $authenticatedUser->id,
                    'user_role_id' => $userRole->id,
                    'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                    'role' => $userRole->roleId
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar tus escuelas: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }
    
    public function show($id)
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            
            if (!$userRole || !in_array($userRole->roleId, [2])) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para ver las escuelas',
                    'timestamp' => now(),
                ], 403);
            }

            $school = Schools::with(['schoolTypes', 'schoolUsers'])
                ->where('id', $id)
                ->where('status', true)
                ->whereHas('schoolUsers', function($query) use ($userRole) {
                    $query->where('userRoleId', $userRole->id);
                })
                ->first();

            if (!$school) {
                return response()->json([
                    'success' => false,
                    'message' => 'Escuela no encontrada o no tienes permisos para verla',
                    'timestamp' => now(),
                ], 404);
            }

            $types = $school->schoolTypes->map(function ($schoolType) {
                return [
                    'id' => $schoolType->id,
                    'type' => $schoolType->type,
                    'type_name' => $this->getTypeName($schoolType->type)
                ];
            });

            $currentUserSchoolUser = $school->schoolUsers->where('userRoleId', $userRole->id)->first();

            $additionalInfo = [];
            
            if ($userRole->roleId == 2) {
                $directorSchoolUsers = $school->schoolUsers->where('userRoleId', '!=', $userRole->id);
                
                $assignedDirectors = [];
                foreach ($directorSchoolUsers as $directorSchoolUser) {
                    $directorRole = UserRole::find($directorSchoolUser->userRoleId);
                    if ($directorRole && $directorRole->roleId == 3) {
                        $director = User::find($directorRole->userId);
                        if ($director && $director->status) {
                            $assignedDirectors[] = [
                                'director_id' => $director->id,
                                'director_role_id' => $directorRole->id,
                                'name' => $director->firstName . ' ' . $director->lastName,
                                'email' => $director->email,
                                'phone' => $director->phone,
                                'school_user_id' => $directorSchoolUser->id
                            ];
                        }
                    }
                }
                
                $additionalInfo = [
                    'user_type' => 'owner',
                    'assigned_directors' => $assignedDirectors,
                    'total_directors' => count($assignedDirectors)
                ];
                
            } 

            $schoolData = [
                'id' => $school->id,
                'name' => $school->name,
                'address' => $school->address,
                'phone' => $school->phone,
                'city' => $school->city,
                'status' => $school->status,
                'created_at' => $school->created_at,
                'school_types' => $types,
                'total_types' => $types->count(),
                'access_info' => [
                    'school_user_id' => $currentUserSchoolUser ? $currentUserSchoolUser->id : null,
                    'user_role_id' => $userRole->id,
                    'access_level' => $userRole->roleId,
                ],
                'team_info' => $additionalInfo
            ];

            return response()->json([
                'success' => true,
                'message' => 'Escuela encontrada exitosamente',
                'data' => $schoolData,
                'user_info' => [
                    'user_id' => $authenticatedUser->id,
                    'user_role_id' => $userRole->id,
                    'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                    'role' => $userRole->roleId,
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar la escuela: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function create(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:100',
                'address' => 'required|string',
                'phone' => 'required|string|max:10',
                'city' => 'required|string|max:50',
                'school_types' => 'required|array|min:1|max:3',
                'school_types.*' => 'required|integer|in:1,2,3',
                'director_id' => 'nullable|integer|exists:users,id', // Opcional
            ]);

            if ($validator->fails()) {
                $errors = $validator->errors();
                if ($errors->has('name')) {
                    $msg = 'El nombre es obligatorio y debe tener máximo 100 caracteres.';
                } elseif ($errors->has('address')) {
                    $msg = 'La dirección es obligatoria.';
                } elseif ($errors->has('phone')) {
                    $msg = 'El teléfono es obligatorio y debe tener máximo 10 dígitos.';
                } elseif ($errors->has('city')) {
                    $msg = 'La ciudad es obligatoria y debe tener máximo 50 caracteres.';
                } elseif ($errors->has('school_types')) {
                    $msg = 'Debe seleccionar al menos un tipo de escuela (1, 2 o 3).';
                } elseif ($errors->has('director_id')) {
                    $msg = 'El director seleccionado no existe.';
                } else {
                    $msg = 'Datos inválidos.';
                }
                return response()->json([
                    'success' => false,
                    'message' => $msg,
                    'errors' => $errors,
                    'timestamp' => now(),
                ], 400);
            }

            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            
            if (!$userRole || !in_array($userRole->roleId, [2])) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para crear escuelas',
                    'timestamp' => now(),
                ], 403);
            }

            // Validar director si se proporciona
            $directorRole = null;
            $directorUser = null;
            if ($request->director_id) {
                // Verificar que el director existe y fue creado por este owner
                $directorRole = UserRole::where('userId', $request->director_id)
                    ->where('roleId', 3) // Debe ser director
                    ->where('createdBy', $authenticatedUser->id) // Creado por este owner
                    ->first();
                    
                if (!$directorRole) {
                    return response()->json([
                        'success' => false,
                        'message' => 'El director seleccionado no existe o no fue creado por ti',
                        'timestamp' => now(),
                    ], 400);
                }
                
                $directorUser = User::find($request->director_id);
            }

            $typeMapping = [
                1 => 'kindergarten',
                2 => 'day_care', 
                3 => 'preschool'
            ];

            DB::beginTransaction();

            try {
                // 1. Crear la escuela
                $school = Schools::create([
                    'name' => $request->name,
                    'address' => $request->address,
                    'phone' => $request->phone,
                    'city' => $request->city,
                    'status' => true,
                ]);

                // 2. Crear los tipos de escuela
                $schoolTypes = [];
                foreach ($request->school_types as $typeNumber) {
                    $schoolType = SchoolTypes::create([
                        'schoolId' => $school->id,
                        'type' => $typeMapping[$typeNumber]
                    ]);
                    $schoolTypes[] = $schoolType;
                }

                // 3. Crear el registro en school_users para el OWNER (creador)
                $ownerSchoolUser = SchoolUsers::create([
                    'schoolId' => $school->id,
                    'userRoleId' => $userRole->id
                ]);

                // 4. Crear el registro en school_users para el DIRECTOR (si se asignó)
                $directorSchoolUser = null;
                if ($directorRole) {
                    $directorSchoolUser = SchoolUsers::create([
                        'schoolId' => $school->id,
                        'userRoleId' => $directorRole->id
                    ]);
                }

                DB::commit();

                $typesCreated = array_map(function($type) {
                    return [
                        'id' => $type->id,
                        'type' => $type->type,
                        'type_name' => $this->getTypeName($type->type)
                    ];
                }, $schoolTypes);

                $assignedDirector = null;
                if ($directorUser && $directorRole) {
                    $assignedDirector = [
                        'user_id' => $directorUser->id,
                        'user_role_id' => $directorRole->id,
                        'name' => $directorUser->firstName . ' ' . $directorUser->lastName,
                        'email' => $directorUser->email,
                        'school_user_id' => $directorSchoolUser->id
                    ];
                }

                return response()->json([
                    'success' => true,
                    'message' => 'Escuela creada exitosamente' . ($assignedDirector ? ' con director asignado' : ''),
                    'data' => [
                        'school' => $school,
                        'school_types' => $typesCreated,
                        'total_types' => count($schoolTypes),
                        'created_by' => [
                            'user_id' => $authenticatedUser->id,
                            'user_role_id' => $userRole->id,
                            'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                            'role' => $userRole->roleId,
                            'school_user_id' => $ownerSchoolUser->id
                        ],
                        'assigned_director' => $assignedDirector,
                    ],
                    'timestamp' => now(),
                ], 201);

            } catch (\Exception $e) {
                DB::rollback();
                throw $e;
            }

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al crear la escuela: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    private function getTypeName($type)
    {
        $names = [
            'kindergarten' => 'Jardín de Niños',
            'day_care' => 'Guardería',
            'preschool' => 'Preescolar'
        ];
        
        return $names[$type] ?? $type;
    }

    public function edit(Request $request, $id)
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();

            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();

            if (!$userRole || $userRole->roleId != 2) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para editar escuelas',
                    'timestamp' => now(),
                ], 403);
            }

            $school = Schools::find($id);

            if (!$school || !$school->status) {
                return response()->json([
                    'success' => false,
                    'message' => 'Escuela no encontrada o está inactiva',
                    'timestamp' => now(),
                ], 404);
            }

            $schoolUser = SchoolUsers::where('schoolId', $id)
                ->where('userRoleId', $userRole->id)
                ->first();

            if (!$schoolUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para editar esta escuela. Solo puedes editar escuelas que tú creaste.',
                    'timestamp' => now(),
                ], 403);
            }

            // Validar los datos a editar
            $validator = Validator::make($request->all(), [
                'name' => 'sometimes|string|max:100',
                'address' => 'sometimes|string',
                'phone' => 'sometimes|string|max:10',
                'city' => 'sometimes|string|max:50',
                'school_types' => 'sometimes|array|min:1|max:3',
                'school_types.*' => 'required_with:school_types|integer|in:1,2,3',
                'director_id' => 'sometimes|integer|exists:users,id', 
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Datos inválidos para editar la escuela',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            DB::beginTransaction();

            try {
                // Actualizar los campos permitidos
                $school->update($validator->validated());

                // Si school_types viene en el request, actualiza los tipos
                if ($request->has('school_types')) {
                    $typeMapping = [
                        1 => 'kindergarten',
                        2 => 'day_care',
                        3 => 'preschool'
                    ];

                    // Eliminar los tipos anteriores
                    SchoolTypes::where('schoolId', $school->id)->delete();

                    // Crear los nuevos tipos
                    foreach ($request->school_types as $typeNumber) {
                        SchoolTypes::create([
                            'schoolId' => $school->id,
                            'type' => $typeMapping[$typeNumber]
                        ]);
                    }
                }

                if ($request->has('director_id')) {
                    $directorUserRole = UserRole::where('userId', $request->director_id)->first();

                    if ($directorUserRole) {
                        // Buscar en school_users el registro con ese userRoleId y schoolId
                        $directorSchoolUser = SchoolUsers::where('schoolId', $school->id)
                            ->where('userRoleId', $directorUserRole->id)
                            ->first();

                        $directorSchoolUserId = $directorSchoolUser ? $directorSchoolUser->id : null;

                        // Si no existe el registro, actualiza el segundo registro de school_users que es sí o sí, director
                        if (!$directorSchoolUser) {
                            $secondSchoolUser = SchoolUsers::where('schoolId', $school->id)
                                ->orderBy('id', 'asc')
                                ->skip(1)
                                ->first();

                            if ($secondSchoolUser) {
                                $secondSchoolUser->userRoleId = $directorUserRole->id;
                                $secondSchoolUser->save();
                            } else {
                                // Si no hay segundo registro, crea uno nuevo para el director
                                SchoolUsers::create([
                                    'schoolId' => $school->id,
                                    'userRoleId' => $directorUserRole->id
                                ]);
                            }
                        }
                    }
                }

                DB::commit();

                // Obtener los tipos actualizados para la respuesta
                $types = SchoolTypes::where('schoolId', $school->id)->get()->map(function ($schoolType) {
                    return [
                        'id' => $schoolType->id,
                        'type' => $schoolType->type,
                        'type_name' => $this->getTypeName($schoolType->type)
                    ];
                });

                return response()->json([
                    'success' => true,
                    'message' => 'Escuela editada exitosamente',
                    'data' => [
                        'school' => $school,
                        'school_types' => $types,
                        'total_types' => $types->count(),
                        'edited_by' => [
                            'user_id' => $authenticatedUser->id,
                            'user_role_id' => $userRole->id,
                            'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                            'role' => $userRole->roleId
                        ]
                    ],
                    'timestamp' => now(),
                ], 200);

            } catch (\Exception $e) {
                DB::rollback();
                return response()->json([
                    'success' => false,
                    'message' => 'Error al editar la escuela: ' . $e->getMessage(),
                    'timestamp' => now(),
                ], 500);
            }

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al editar la escuela: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function delete($id)
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            
            if (!$userRole || !in_array($userRole->roleId, [2])) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para eliminar escuelas',
                    'timestamp' => now(),
                ], 403);
            }

            $school = Schools::find($id);
            
            if (!$school) {
                return response()->json([
                    'success' => false,
                    'message' => 'Escuela no encontrada',
                    'timestamp' => now(),
                ], 404);
            }

            $schoolUser = SchoolUsers::where('schoolId', $id)
                ->where('userRoleId', $userRole->id)
                ->first();

            if (!$schoolUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para eliminar esta escuela. Solo puedes eliminar escuelas que tú creaste.',
                    'timestamp' => now(),
                ], 403);
            }

            if (!$school->status) {
                return response()->json([
                    'success' => false,
                    'message' => 'La escuela ya está inactiva',
                    'timestamp' => now(),
                ], 400);
            }

            $school->update([
                'status' => false,
            ]);

            $schoolTypes = SchoolTypes::where('schoolId', $id)->get();
            $types = $schoolTypes->map(function ($schoolType) {
                return [
                    'id' => $schoolType->id,
                    'type' => $schoolType->type,
                    'type_name' => $this->getTypeName($schoolType->type)
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Escuela eliminada (inactivada) exitosamente',
                'data' => [
                    'deleted_school' => [
                        'id' => $school->id,
                        'name' => $school->name,
                        'address' => $school->address,
                        'phone' => $school->phone,
                        'city' => $school->city,
                        'status' => $school->status,
                        'created_at' => $school->created_at,
                        'school_types' => $types,
                        'total_types' => $types->count(),
                    ],
                    'deleted_by' => [
                        'user_id' => $authenticatedUser->id,
                        'user_role_id' => $userRole->id,
                        'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                        'role' => $userRole->roleId
                    ],
                    'ownership_info' => [
                        'school_user_id' => $schoolUser->id,
                        'user_role_id' => $userRole->id,
                        'was_owner' => true
                    ]
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al eliminar escuela: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function mySchools()
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();

            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            if (!$userRole || $userRole->roleId != 2) {
                return response()->json([
                    'success' => false,
                    'message' => 'Solo los dueños pueden consultar sus escuelas',
                    'timestamp' => now(),
                ], 403);
            }

            // Buscar todas las escuelas activas donde el dueño es el único registro en school_users
            $schoolUserIds = SchoolUsers::where('userRoleId', $userRole->id)
                ->pluck('schoolId')
                ->toArray();

            // Filtrar solo las escuelas donde solo hay un registro en school_users (solo el dueño)
            $schools = Schools::whereIn('id', $schoolUserIds)
                ->where('status', true)
                ->get()
                ->filter(function ($school) {
                    return SchoolUsers::where('schoolId', $school->id)->count() === 1;
                })
                ->values();

            $schoolsData = $schools->map(function ($school) {
                return [
                    'id' => $school->id,
                    'name' => $school->name,
                    'address' => $school->address,
                    'phone' => $school->phone,
                    'city' => $school->city,
                    'status' => $school->status,
                    'created_at' => $school->created_at
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Escuelas activas sin director encontradas exitosamente',
                'data' => $schoolsData,
                'total_schools' => $schools->count(),
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar tus escuelas: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    // public function revive($id) algo para poder revivir a la escuela eliminada quizá?
}
