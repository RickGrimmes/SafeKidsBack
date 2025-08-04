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
        DB::statement("ALTER TABLE attendance_infos MODIFY COLUMN pickedUpById BIGINT UNSIGNED NULL");
        DB::statement("ALTER TABLE attendance_infos MODIFY COLUMN pickedUpByType VARCHAR(50) NULL");
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        DB::statement("ALTER TABLE attendance_infos MODIFY COLUMN pickedUpById BIGINT UNSIGNED NOT NULL");
        DB::statement("ALTER TABLE attendance_infos MODIFY COLUMN pickedUpByType VARCHAR(50) NOT NULL");
    }
};
