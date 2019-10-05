<?php

namespace Azuriom\Http\Controllers\Admin;

use Azuriom\Http\Controllers\Controller;
use Azuriom\Models\ActionLog;

class ActionLogController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $logs = ActionLog::with('target')
            ->latest()
            ->paginate(25);

        return view('admin.logs.index')->with('logs', $logs);
    }
}
