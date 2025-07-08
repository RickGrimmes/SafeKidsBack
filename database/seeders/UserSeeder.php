<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        User::create([
            'firstName' => 'Administrador',
            'lastName' => 'Safe Kids',
            'email' => 'safekidstrc@gmail.com',
            'password' => Hash::make('apeslpyo'),
            'phone' => '1234567890',
            'status' => true,
            '2facode' => null,
            'profilePhoto' => 'default.jpg',
        ]);
    }
}
