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
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('firstName', 100);
            $table->string('lastName', 100);
            $table->string('email', 100)->unique();
            $table->string('password', 500);
            $table->string('phone', 10);
            $table->boolean('status');
            $table->string('2facode', 6)->nullable();
            $table->text('profilePhoto');
            $table->timestamp('created_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('users');
    }
};
