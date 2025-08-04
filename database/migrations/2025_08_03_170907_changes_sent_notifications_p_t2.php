<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Elimina las claves foráneas
        DB::statement('ALTER TABLE sent_notifications DROP FOREIGN KEY sent_notifications_guardian1id_foreign');
        DB::statement('ALTER TABLE sent_notifications DROP FOREIGN KEY sent_notifications_guardian2id_foreign');

        // Modifica los campos para que sean solo enteros y guardian2Id nullable
        DB::statement('ALTER TABLE sent_notifications MODIFY guardian1Id BIGINT UNSIGNED NOT NULL');
        DB::statement('ALTER TABLE sent_notifications MODIFY guardian2Id BIGINT UNSIGNED NULL');
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::table('sent_notifications', function (Blueprint $table) {
            //
        });
    }
};
