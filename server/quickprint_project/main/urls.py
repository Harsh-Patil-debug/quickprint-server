"""
QuickPrint — URL Routes
All API routes mounted under: /api/v1/main/
"""
from django.urls import path
from .views import *

app_name = 'main'

urlpatterns = [

    # ── Status ────────────────────────────────────────────────────────────────
    path('status/', StatusCheckView.as_view(), name='status'),

    # ── Customer auth ────────────────────────────────────────────────────────
    path('auth/register/', CustomerRegisterView.as_view(), name='customer_register'),
    path('auth/login/', CustomerLoginView.as_view(), name='customer_login'),
    path('auth/verify-otp/', CustomerVerifyOTPView.as_view(), name='customer_verify_otp'),
    path('auth/resend-otp/', CustomerResendOTPView.as_view(), name='customer_resend_otp'),
    path('auth/forgot-password/', CustomerForgotPasswordView.as_view(), name='customer_forgot_password'),
    path('auth/reset-password/', CustomerResetPasswordView.as_view(), name='customer_reset_password'),
    path('auth/google/login/', CustomerGoogleLoginRedirectView.as_view(), name='customer_google_login'),
    path('auth/google/callback/', CustomerGoogleCallbackView.as_view(), name='customer_google_callback'),
    path('auth/logout/', CustomerLogoutView.as_view(), name='customer_logout'),
    path('auth/me/', CustomerMeView.as_view(), name='customer_me'),
    path('auth/delete-account/', CustomerDeleteAccountView.as_view(), name='customer_delete_account'),
    path('auth/refresh/', CustomerRefreshView.as_view(), name='customer_refresh'),

    # ── Super admin auth ─────────────────────────────────────────────────────
    path('super-admin/register/', SuperAdminRegisterView.as_view(), name='super_admin_register'),
    path('super-admin/login/', SuperAdminLoginView.as_view(), name='super_admin_login'),
    path('super-admin/verify-otp/', SuperAdminVerifyOTPView.as_view(), name='super_admin_verify_otp'),
    path('super-admin/resend-otp/', SuperAdminResendOTPView.as_view(), name='super_admin_resend_otp'),
    path('super-admin/forgot-password/', SuperAdminForgotPasswordView.as_view(), name='super_admin_forgot_password'),
    path('super-admin/reset-password/', SuperAdminResetPasswordView.as_view(), name='super_admin_reset_password'),
    path('super-admin/logout/', SuperAdminLogoutView.as_view(), name='super_admin_logout'),
    path('super-admin/me/', SuperAdminMeView.as_view(), name='super_admin_me'),
    path('super-admin/refresh/', SuperAdminRefreshView.as_view(), name='super_admin_refresh'),
    path('super-admin/invites/', SuperAdminInviteListCreateView.as_view(), name='super_admin_invites'),
    path('super-admin/invites/<str:email>/', SuperAdminInviteDetailView.as_view(), name='super_admin_invite_detail'),

    # ── Partner applications ─────────────────────────────────────────────────
    path('partner-applications/', PartnerApplicationListCreateView.as_view(), name='partner_applications'),
    path('partner-applications/<str:app_id>/', PartnerApplicationDetailView.as_view(), name='partner_application_detail'),

    # ── Shop staff auth ──────────────────────────────────────────────────────
    path('shop-auth/register/', ShopStaffRegisterView.as_view(), name='shop_staff_register'),
    path('shop-auth/signup/', ShopOwnerSignupView.as_view(), name='shop_owner_signup'),
    path('shop-auth/login/', ShopStaffLoginView.as_view(), name='shop_staff_login'),
    path('shop-auth/verify-otp/', ShopStaffVerifyOTPView.as_view(), name='shop_staff_verify_otp'),
    path('shop-auth/resend-otp/', ShopStaffResendOTPView.as_view(), name='shop_staff_resend_otp'),
    path('shop-auth/forgot-password/', ShopStaffForgotPasswordView.as_view(), name='shop_staff_forgot_password'),
    path('shop-auth/reset-password/', ShopStaffResetPasswordView.as_view(), name='shop_staff_reset_password'),
    path('shop-auth/logout/', ShopStaffLogoutView.as_view(), name='shop_staff_logout'),
    path('shop-auth/me/', ShopStaffMeView.as_view(), name='shop_staff_me'),
    path('shop-auth/refresh/', ShopStaffRefreshView.as_view(), name='shop_staff_refresh'),

    # ── Shops ─────────────────────────────────────────────────────────────────
    path('shops/', ShopListView.as_view(), name='shops'),
    path('shops/seed/', ShopSeedView.as_view(), name='shops_seed'),
    path('shops/parse-maps-url/', ShopParseMapsUrlView.as_view(), name='shops_parse_maps_url'),
    path('shop/profile/', ShopProfileView.as_view(), name='shop_profile'),
    path('shops/<str:shop_id>/', ShopDetailView.as_view(), name='shop_detail'),

    # ── Shops (super admin) ──────────────────────────────────────────────────
    path('admin/shops/', AdminShopListCreateView.as_view(), name='admin_shops'),
    path('admin/shops/upload-image/', AdminShopImageUploadView.as_view(), name='admin_shop_upload_image'),
    path('admin/shops/<str:shop_id>/', AdminShopDetailView.as_view(), name='admin_shop_detail'),
    path('admin/shops/<str:shop_id>/restore/', AdminShopRestoreView.as_view(), name='admin_shop_restore'),

    # ── Uploads ───────────────────────────────────────────────────────────────
    path('uploads/document/', PrintDocumentUploadView.as_view(), name='upload_document'),

    # ── Orders (customer) ────────────────────────────────────────────────────
    path('orders/draft/', OrderDraftCreateView.as_view(), name='order_draft_create'),
    path('orders/mine/', MyOrdersListView.as_view(), name='orders_mine'),
    path('orders/<str:order_id>/', OrderDetailView.as_view(), name='order_detail'),
    path('orders/<str:order_id>/confirm/', OrderConfirmPaymentView.as_view(), name='order_confirm_payment'),

    # ── Orders (shop dashboard) ──────────────────────────────────────────────
    path('shop/queue/', ShopQueueListView.as_view(), name='shop_queue'),
    path('shop/orders/', ShopOrderHistoryView.as_view(), name='shop_order_history'),
    path('shop/queue/<str:order_id>/status/', ShopOrderStatusUpdateView.as_view(), name='shop_queue_status_update'),
]
