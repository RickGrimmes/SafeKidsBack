<?php

namespace App\Http\Controllers;

use App\Models\Groups;
use Illuminate\Http\Request;

class GroupController extends Controller
{
    public function index($schoolId)
    {
        $groups = Groups::where('schoolId', $schoolId)->get();

        $uniqueGradeSections = $groups->pluck('gradeSection')->unique()->values();

        return response()->json([
            'success' => true,
            'gradeSections' => $uniqueGradeSections,
            'total' => $uniqueGradeSections->count(),
            'timestamp' => now(),
        ]);
    }
}
