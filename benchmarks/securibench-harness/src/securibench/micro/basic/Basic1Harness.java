package securibench.micro.basic;

public final class Basic1Harness {
    private Basic1Harness() {
    }

    public static void main(String[] args) throws Exception {
        new Basic1().doGet(null, null);
    }
}
