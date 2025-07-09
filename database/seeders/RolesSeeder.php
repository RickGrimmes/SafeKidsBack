<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class RolesSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::table('roles')->insert([
            ['id' => 2, 'name' => 'owner'],
            ['id' => 3, 'name' => 'director'],
            ['id' => 4, 'name' => 'secretary'],
        ]);
    }
}
