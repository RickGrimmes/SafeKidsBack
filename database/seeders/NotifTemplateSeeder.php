<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
USE Illuminate\Support\Facades\DB;

class NotifTemplateSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        DB::table('notification_templates')->insert([
            [
                'message' => 'Tu/s hij@/s [nombreEstudiante] acaba/n de ingresar a la escuela.',
                'type' => 'ENTRADA',
            ],
            [
                'message' => 'Tu/s hij@/s [nombreEstudiante] ha salido de la escuela, junto con ([nombreResponsable]).',
                'type' => 'SALIDA',
            ],
        ]);
    }
}
