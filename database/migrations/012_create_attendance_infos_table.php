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
        Schema::create('attendance_infos', function (Blueprint $table) {
            $table->id();
            $table->foreignId('studentId')->constrained('students')->onDelete('cascade');
            $table->timestamp('checkIn');
            $table->timestamp('checkOut')->nullable();
            $table->timestamp('updatedAt')->nullable();
            $table->unsignedBigInteger('pickedUpById');
            $table->enum('pickedUpByType', ['guardian', 'authorized']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('attendance_infos');
    }
};
