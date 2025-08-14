<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SentNotifications extends Model
{
    use HasFactory;

    /**
     * Indicates if the model should be timestamped.
     */
    public $timestamps = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'guardian1Id',
        'guardian2Id',
        'studentId',
        'attendanceInfoId',
        'message',
        'type',
        'templateId',
        'sentAt',
        'status',
        'created_at',
        'updated_at',
        'last_message',
        'last_type'
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'sentAt' => 'datetime',
        'status' => 'string',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * Relaciones con otras tablas.
     */
    public function guardian1()
    {
        return $this->belongsTo(StudentGuardian::class, 'guardian1Id');
    }

    public function guardian2()
    {
        return $this->belongsTo(StudentGuardian::class, 'guardian2Id');
    }

    public function student()
    {
        return $this->belongsTo(Students::class, 'studentId');
    }

    public function attendanceInfo()
    {
        return $this->belongsTo(AttendanceInfo::class, 'attendanceInfoId');
    }

    public function template()
    {
        return $this->belongsTo(NotificationTemplates::class, 'templateId');
    }
}
