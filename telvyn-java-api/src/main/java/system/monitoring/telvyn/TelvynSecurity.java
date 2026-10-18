package system.monitoring.telvyn;

/**
 * Eventos de usuário e bloqueio para logins que o agente não reconhece sozinho (como o EventTrackerV2 e o
 * {@code Blocking} do Datadog). Sem o agente Java do Telvyn os métodos não fazem nada.
 *
 * <p>Com o agente: o evento sai com o IP, o navegador e o trace da requisição em curso. Quando o usuário de
 * {@link #trackUserLoginSuccess} ou {@link #setUser} está bloqueado na tela, o agente já responde com a página de
 * bloqueio e o método lança uma exceção que encerra a requisição — não a capture. Nunca passe a senha.
 */
public final class TelvynSecurity {
    private TelvynSecurity() {}

    /** Login com sucesso: o login digitado e o id do usuário (sem id, vale o login). */
    public static void trackUserLoginSuccess(String login, String userId) {}

    /** Login com falha: o login digitado e se a conta existe. */
    public static void trackUserLoginFailure(String login, boolean exists) {}

    /** Cadastro: o login e o id do usuário criado (sem id, vale o login). */
    public static void trackUserSignup(String login, String userId) {}

    /** Usuário logado da requisição em curso, para o bloqueio de usuários e as regras sobre o usuário. */
    public static void setUser(String userId) {}

    /** Se o usuário está bloqueado na tela do Telvyn (e o bloqueio está permitido). */
    public static boolean isUserBlocked(String userId) { return false; }
}
