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
        DB::statement("ALTER TABLE sent_notifications ADD COLUMN last_message VARCHAR(300) NULL");
        DB::statement("ALTER TABLE sent_notifications ADD COLUMN last_type ENUM('SALIDA') NULL");
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        DB::statement("ALTER TABLE sent_notifications DROP COLUMN last_message");
        DB::statement("ALTER TABLE sent_notifications DROP COLUMN last_type");
    }
};
