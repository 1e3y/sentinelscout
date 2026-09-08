import type {
  UpdateFindingFollowUpConditionalRequest,
  UpdateFindingFollowUpRequest,
} from "@/lib/api";
import type { ConditionalFindingFollowUpWrite } from "@/lib/update-finding-follow-up-conditional";

type Expect<T extends true> = T;

type LegacyOmitsExpected = Expect<
  "expected_follow_up" extends keyof UpdateFindingFollowUpRequest ? false : true
>;

type ConditionalRequiresExpected = Expect<
  UpdateFindingFollowUpConditionalRequest extends {
    expected_follow_up: {
      assigned_to_user_id: string | null;
      follow_up_due_at: string | null;
    };
  }
    ? true
    : false
>;

type M47WriteRequiresDueAndExpected = Expect<
  ConditionalFindingFollowUpWrite extends {
    assigned_to_user_id: string | null;
    follow_up_due_at: string;
    expected_follow_up: {
      assigned_to_user_id: string | null;
      follow_up_due_at: string | null;
    };
  }
    ? true
    : false
>;

export type M47ClientContract = LegacyOmitsExpected &
  ConditionalRequiresExpected &
  M47WriteRequiresDueAndExpected;
