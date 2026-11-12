(() => {
    const reveal = () => {
        if (window.anime) {
            window.anime({ targets: '.stagger-in', opacity: [0, 1], translateY: [12, 0], delay: window.anime.stagger(90), duration: 600, easing: 'easeOutCubic' });
        }
    };
    document.addEventListener('DOMContentLoaded', reveal);
    document.addEventListener('enhancedload', reveal);
})();

window.razorpayCheckout = async (amount, currency) => {
    if (!window.Razorpay) {
        return { ok: false, message: 'Razorpay Checkout.js did not load.' };
    }

    try {
        const orderResponse = await fetch('/api/payments/razorpay/order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ amount, currency })
        });
        const order = await orderResponse.json().catch(() => ({}));
        if (!orderResponse.ok) {
            return { ok: false, message: order.error || 'Could not create a Razorpay order.' };
        }

        return await new Promise((resolve) => {
            const checkout = new window.Razorpay({
                key: order.keyId,
                amount: order.amount,
                currency: order.currency,
                name: 'razorops',
                description: 'Payment test checkout',
                order_id: order.orderId,
                theme: { color: '#e85d45' },
                handler: async (payment) => {
                    // Always resolve: an unhandled failure here would leave the
                    // caller waiting forever with the button stuck disabled.
                    try {
                        const verifyResponse = await fetch('/api/payments/razorpay/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                orderId: payment.razorpay_order_id,
                                paymentId: payment.razorpay_payment_id,
                                signature: payment.razorpay_signature
                            })
                        });
                        const verification = await verifyResponse.json().catch(() => ({}));
                        resolve({ ok: verifyResponse.ok, message: verification.message || 'Payment verification failed.' });
                    } catch (error) {
                        resolve({ ok: false, message: 'Payment was made but could not be verified. Please contact support.' });
                    }
                },
                modal: { ondismiss: () => resolve({ ok: false, message: 'Checkout was cancelled.' }) }
            });
            checkout.on('payment.failed', (failure) => resolve({ ok: false, message: failure.error?.description || 'Payment failed.' }));
            checkout.open();
        });
    } catch (error) {
        return { ok: false, message: error.message || 'Checkout request failed.' };
    }
};
