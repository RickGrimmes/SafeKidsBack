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
        Schema::create('sent_notifications', function (Blueprint $table) {
            $table->id();
            $table->foreignId('guardian1Id')->constrained('student_guardians')->onDelete('cascade');
            $table->foreignId('guardian2Id')->constrained('student_guardians')->onDelete('cascade');
            $table->foreignId('studentId')->constrained('students')->onDelete('cascade');
            $table->foreignId('attendanceInfoId')->constrained('attendance_infos')->onDelete('cascade');
            $table->text('message');
            $table->string('type', 50);
            $table->foreignId('templateId')->constrained('notification_templates')->onDelete('cascade');
            $table->timestamp('sentAt');
            $table->enum('status', ['sent', 'pending']);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('sent_notifications');
    }
};
