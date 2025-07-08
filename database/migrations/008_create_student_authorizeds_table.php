<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
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
        Schema::create('student_authorizeds', function (Blueprint $table) {
            $table->id();
            $table->foreignId('studentId')->constrained('students')->onDelete('cascade');
            $table->foreignId('authorizedId')->constrained('authorized_people')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('student_authorizeds');
    }
};
