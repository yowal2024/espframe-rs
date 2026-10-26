import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import java.util.concurrent.atomic.AtomicInteger;

/** Runs in its own app_process; tests a local object and reads the remote display service. */
public final class DisplayBinderProbe {
    private static native int run(IBinder binder);

    private static final class LocalDisplay extends Binder {
        final AtomicInteger descriptorCalls = new AtomicInteger();
        final AtomicInteger transactionCalls = new AtomicInteger();

        LocalDisplay() {
            attachInterface(null, "android.hardware.display.IDisplayManager");
        }

        @Override
        public String getInterfaceDescriptor() {
            descriptorCalls.incrementAndGet();
            return "android.hardware.display.IDisplayManager";
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            transactionCalls.incrementAndGet();
            return false;
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException("expected absolute probe .so path");
        }
        System.load(args[0]);
        LocalDisplay service = new LocalDisplay();
        int rejected = run(service);
        int descriptors = service.descriptorCalls.get();
        int transactions = service.transactionCalls.get();
        if (rejected != 2 || descriptors != 0 || transactions != 0) {
            throw new AssertionError("local Binder guard failed: rejected=" + rejected
                    + " descriptors=" + descriptors + " transactions=" + transactions);
        }
        System.out.println("PASS: Auto local=JNI remote=Binder twice each; forced local rejected; descriptor=0 transactions=0");
    }
}
