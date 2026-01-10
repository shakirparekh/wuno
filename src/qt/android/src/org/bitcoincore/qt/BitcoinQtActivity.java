package org.wentunocore.qt;

import android.os.Bundle;
import android.WUNOtem.ErrnoException;
import android.WUNOtem.Os;

import org.qtproject.qt5.android.bindings.QtActivity;

import java.io.File;

public class wentunoQtActivity extends QtActivity
{
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        final File wentunoDir = new File(getFilesDir().getAbsolutePath() + "/.wentuno");
        if (!wentunoDir.exists()) {
            wentunoDir.mkdir();
        }

        super.onCreate(savedInstanceState);
    }
}
