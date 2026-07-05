"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import PropTypes from "prop-types";
import { Modal, Button, Input } from "@/shared/components";
import { useCopyToClipboard } from "@/shared/hooks/useCopyToClipboard";

/**
 * Kiro Microsoft 365 (Entra ID) OAuth Modal
 * Drives the Kiro hosted-portal SSO flow: opens the browser sign-in URL, then
 * polls the server (which runs a loopback listener on :3128) until the enterprise
 * external-IdP leg completes.
 *
 * The loopback listener runs on the 9router HOST. When 9router is remote, the
 * operator must forward the port first: ssh -L 3128:127.0.0.1:3128 root@host
 */
export default function KiroMicrosoftOAuthModal({ isOpen, onSuccess, onClose }) {
  // region → operator enters AWS Region, then clicks "Bắt đầu đăng nhập"
  // loading | signing | success | error → session lifecycle after that
  const [step, setStep] = useState("region");
  const [region, setRegion] = useState("us-east-1");
  const [signInUrl, setSignInUrl] = useState("");
  const [error, setError] = useState(null);
  const { copied, copy } = useCopyToClipboard();

  const sessionRef = useRef(null);
  const pollRef = useRef(null);
  const openedRef = useRef(false);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const cancelSession = useCallback(() => {
    const sessionId = sessionRef.current;
    if (!sessionId) return;
    sessionRef.current = null;
    // Fire-and-forget: free the loopback port on the server.
    fetch("/api/oauth/kiro/sso", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "cancel", sessionId }),
    }).catch(() => {});
  }, []);

  const handleClose = useCallback(() => {
    stopPolling();
    cancelSession();
    onClose?.();
  }, [stopPolling, cancelSession, onClose]);

  // Reset back to the region step when the modal closes so it re-opens cleanly.
  // Deferred to a microtask so the resets don't run synchronously in the effect.
  useEffect(() => {
    if (isOpen) return;
    openedRef.current = false;
    stopPolling();
    Promise.resolve().then(() => {
      setStep("region");
      setError(null);
      setSignInUrl("");
    });
  }, [isOpen, stopPolling]);

  // beginSession starts a fresh SSO session for the chosen region, opens the
  // browser once, and polls until completion / error / timeout. Triggered when
  // the operator clicks "Bắt đầu đăng nhập" (or "Try Again").
  const beginSession = useCallback(async () => {
    const chosenRegion = region.trim() || "us-east-1";
    try {
      setError(null);
      setStep("loading");

      const res = await fetch("/api/oauth/kiro/sso", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "start", region: chosenRegion }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start sign-in");

      sessionRef.current = data.sessionId;
      setSignInUrl(data.signInUrl);
      setStep("signing");

      if (!openedRef.current) {
        openedRef.current = true;
        window.open(data.signInUrl, "_blank");
      }

      const intervalMs = (data.interval || 2) * 1000;
      pollRef.current = setInterval(async () => {
        const sessionId = sessionRef.current;
        if (!sessionId) return;
        try {
          const pollRes = await fetch("/api/oauth/kiro/sso", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "poll", sessionId }),
          });
          const pollData = await pollRes.json();
          if (!pollRes.ok) throw new Error(pollData.error || "Sign-in failed");
          if (pollData.completed) {
            stopPolling();
            sessionRef.current = null;
            setStep("success");
            onSuccess?.();
          }
        } catch (err) {
          stopPolling();
          sessionRef.current = null;
          setError(err.message);
          setStep("error");
        }
      }, intervalMs);
    } catch (err) {
      setError(err.message);
      setStep("error");
    }
  }, [region, stopPolling, onSuccess]);

  const handleRetry = () => {
    openedRef.current = false;
    setStep("region");
    setError(null);
  };

  return (
    <Modal isOpen={isOpen} title="Connect Kiro via Microsoft 365" onClose={handleClose} size="lg">
      <div className="flex flex-col gap-4">
        {step === "region" && (
          <>
            <div className="bg-sidebar p-4 rounded-lg border border-border">
              <p className="text-sm text-text-muted">
                Thêm tài khoản Microsoft 365 / Entra ID (Azure AD) qua Kiro hosted SSO
              </p>
            </div>

            <div className="bg-sidebar p-4 rounded-lg border border-border">
              <p className="text-sm text-text-muted text-center">
                Mở link đăng nhập trên chính máy này (cùng host với proxy). Trình duyệt sẽ tự động
                chuyển hướng qua trang đăng nhập Microsoft 365 của bạn.
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">Khu vực</label>
              <Input
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                placeholder="us-east-1"
                className="font-mono text-sm"
              />
              <p className="text-xs text-text-muted mt-1">
                AWS Region cho tài khoản Kiro (mặc định: us-east-1)
              </p>
            </div>

            {error && (
              <div className="bg-red-50 dark:bg-red-900/20 p-3 rounded-lg border border-red-200 dark:border-red-800">
                <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              </div>
            )}

            <div className="flex gap-2">
              <Button onClick={handleClose} variant="ghost" fullWidth>
                Quay lại
              </Button>
              <Button onClick={beginSession} fullWidth disabled={!region.trim()}>
                Bắt đầu đăng nhập
              </Button>
            </div>
          </>
        )}

        {step === "loading" && (
          <div className="text-center py-6">
            <div className="size-16 mx-auto mb-4 rounded-full bg-primary/10 flex items-center justify-center">
              <span className="material-symbols-outlined text-3xl text-primary animate-spin">
                progress_activity
              </span>
            </div>
            <h3 className="text-lg font-semibold mb-2">Initializing...</h3>
            <p className="text-sm text-text-muted">Setting up Microsoft 365 sign-in</p>
          </div>
        )}

        {step === "signing" && (
          <>
            <div className="bg-amber-50 dark:bg-amber-900/20 p-3 rounded-lg border border-amber-200 dark:border-amber-800">
              <div className="flex gap-2">
                <span className="material-symbols-outlined text-amber-600 dark:text-amber-400">info</span>
                <div className="flex-1 text-sm text-amber-800 dark:text-amber-200">
                  <p className="font-medium text-amber-900 dark:text-amber-100 mb-1">
                    Port forwarding required for remote 9router
                  </p>
                  <p>
                    The sign-in redirects to <span className="font-mono">localhost:3128</span> on the
                    9router host. If 9router runs remotely, forward the port first:
                  </p>
                  <code className="mt-2 block rounded bg-black/10 dark:bg-black/30 px-2 py-1 font-mono text-xs">
                    ssh -L 3128:127.0.0.1:3128 root@your-host
                  </code>
                </div>
              </div>
            </div>

            <div className="text-center py-2">
              <div className="size-14 mx-auto mb-3 rounded-full bg-primary/10 flex items-center justify-center">
                <span className="material-symbols-outlined text-2xl text-primary animate-spin">
                  progress_activity
                </span>
              </div>
              <h3 className="text-base font-semibold mb-1">Waiting for sign-in...</h3>
              <p className="text-sm text-text-muted">
                Complete the Microsoft login in the browser tab that opened.
              </p>
            </div>

            <div>
              <p className="text-sm font-medium mb-2">Sign-in URL (open manually if no tab opened)</p>
              <div className="flex gap-2">
                <Input value={signInUrl} readOnly className="flex-1 font-mono text-xs" />
                <Button
                  variant="secondary"
                  icon={copied === "signin_url" ? "check" : "content_copy"}
                  onClick={() => copy(signInUrl, "signin_url")}
                >
                  Copy
                </Button>
              </div>
            </div>

            <Button onClick={handleClose} variant="ghost" fullWidth>
              Cancel
            </Button>
          </>
        )}

        {step === "success" && (
          <div className="text-center py-6">
            <div className="size-16 mx-auto mb-4 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
              <span className="material-symbols-outlined text-3xl text-green-600">check_circle</span>
            </div>
            <h3 className="text-lg font-semibold mb-2">Connected Successfully!</h3>
            <p className="text-sm text-text-muted mb-4">
              Your Kiro account via Microsoft 365 has been connected.
            </p>
            <Button onClick={handleClose} fullWidth>
              Done
            </Button>
          </div>
        )}

        {step === "error" && (
          <div className="text-center py-6">
            <div className="size-16 mx-auto mb-4 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
              <span className="material-symbols-outlined text-3xl text-red-600">error</span>
            </div>
            <h3 className="text-lg font-semibold mb-2">Connection Failed</h3>
            <p className="text-sm text-red-600 mb-4">{error}</p>
            <div className="flex gap-2">
              <Button onClick={handleRetry} variant="secondary" fullWidth>
                Try Again
              </Button>
              <Button onClick={handleClose} variant="ghost" fullWidth>
                Cancel
              </Button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

KiroMicrosoftOAuthModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onSuccess: PropTypes.func,
  onClose: PropTypes.func.isRequired,
};
