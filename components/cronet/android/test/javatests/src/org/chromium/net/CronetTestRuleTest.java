// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.fail;

import android.os.Build;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.SmallTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;

import org.chromium.base.test.util.Batch;
import org.chromium.net.CronetTestRule.CronetImplementation;
import org.chromium.net.CronetTestRule.IgnoreFor;
import org.chromium.net.CronetTestRule.RequiresMinAndroidApi;
import org.chromium.net.CronetTestRule.RequiresMinApi;
import org.chromium.net.impl.CronetUrlRequestContext;

/** Tests features of CronetTestRule. */
@RunWith(AndroidJUnit4.class)
@Batch(Batch.UNIT_TESTS)
public class CronetTestRuleTest {
    @Rule public final CronetTestRule mTestRule = CronetTestRule.withAutomaticEngineStartup();
    @Rule public final TestName mTestName = new TestName();

    /**
     * For any test whose name contains "MustRun", it's enforced that the test must run and set
     * {@code mTestWasRun} to {@code true}.
     */
    private boolean mTestWasRun;

    /**
     * This is used by testAllImplsMustRun. That test relies on the fact that reruns for multiple
     * implementations do not re-instantiate the test class (instead, only setUp is run again). This
     * means that "modifications" applied to a class variable will be visible to reruns of the same
     * test that target a different Cronet implementation.
     */
    private int mNumberOfReruns;

    private boolean mFallbackImplWasRun;
    private boolean mNativeImplWasRun;
    private boolean mPlatformImplWasRun;

    @Before
    public void setUp() throws Exception {
        mTestWasRun = false;
    }

    @After
    public void tearDown() throws Exception {
        if (mTestName.getMethodName().contains("MustRun") && !mTestWasRun) {
            fail(mTestName.getMethodName() + " should have run but didn't.");
        }
    }

    @Test
    @SmallTest
    @RequiresMinApi(999999999)
    public void testRequiresMinApiDisable() {
        fail("RequiresMinApi failed to disable.");
    }

    @Test
    @SmallTest
    @RequiresMinApi(-999999999)
    public void testRequiresMinApiMustRun() {
        mTestWasRun = true;
    }

    /**
     * This test relies on seeing reruns side-effects through {@code mNumberOfReruns}. More info in
     * {@code mNumberOfReruns}'s Javadoc.
     */
    @Test
    @SmallTest
    @IgnoreFor(
            implementations = {CronetImplementation.FALLBACK, CronetImplementation.AOSP_PLATFORM},
            reason = "Testing the rule")
    public void testRunOnlyNativeMustRun() {
        assertThat(mTestRule.testingJavaImpl()).isFalse();
        assertThat(mTestRule.implementationUnderTest())
                .isEqualTo(CronetImplementation.STATICALLY_LINKED);
        assertThat(mTestWasRun).isFalse();
        mTestWasRun = true;
        assertThat(mTestRule.getTestFramework().getEngine())
                .isInstanceOf(CronetUrlRequestContext.class);
    }
}
