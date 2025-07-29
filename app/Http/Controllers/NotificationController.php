<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class NotificationController extends Controller
{
    public function create()
    {
        // toma el id del chiquillo 
        return response()->json(['message' => 'This is a test endpoint for notifications.']);
    }
}
