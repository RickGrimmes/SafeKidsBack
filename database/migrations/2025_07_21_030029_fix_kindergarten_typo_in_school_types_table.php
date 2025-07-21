<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up()
    {
        DB::statement("ALTER TABLE school_types MODIFY COLUMN type ENUM('kindergarten', 'day_care', 'preschool')");
    }

    public function down()
    {
        DB::statement("ALTER TABLE school_types MODIFY COLUMN type ENUM('kindergarte', 'day_care', 'preschool')");
    }
};